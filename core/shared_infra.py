#!/usr/bin/env python3
"""
ZYLON FUSION - Shared Infrastructure Layer
===========================================
Centralized, thread-safe, production-ready utilities shared across all 40+ engines.

Fixes & Improvements Addressed:
  Bug #4  - Thread-unsafe requests.Session → ThreadSafeSession with lock + pooling
  Imp #1  - No async support              → AsyncSession with aiohttp + semaphore
  Imp #2  - Payload injection outdated    → PayloadInjector (GET/POST/JSON/XML/Header/Multipart/All)
  Imp #4  - No OOB testing               → OOBProvider (interact.sh / dnslog.cn / local fallback)
  Imp #5  - Regex recompilation          → RegexCache singleton with pre-compiled COMMON_PATTERNS
  Imp #6  - Modern SPA blind spots       → ModernFrameworkDiscovery (source maps, Next.js, webpack)

Thread safety is CRITICAL — threading.Lock is used everywhere it is needed.
Python 3.10+ compatible (Termux uses Python 3.13).
Only standard library + requests + aiohttp are used.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import string
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
import requests.adapters

from core.var import USER_AGENTS, DEFAULT_TIMEOUT, VERIFY_SSL, MAX_THREADS


# ============================================================================
# WAFEvasionMixin
# ============================================================================


class WAFEvasionMixin:
    """Mixin providing WAF evasion capabilities to any engine.

    Injects headers that spoof origin IPs and client metadata so that
    rate-limiting / IP-based WAF rules are harder to enforce.
    """

    WAF_EVASION_HEADERS: List[str] = [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Client-IP",
        "X-Real-IP",
        "True-Client-IP",
        "X-Custom-IP-Authorization",
        "X-Original-URL",
        "X-Rewrite-URL",
    ]

    @staticmethod
    def _random_ip() -> str:
        """Generate a random public-looking IPv4 address."""
        first = random.choice([3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                               20, 21, 22, 23, 24, 25, 26, 28, 29, 30, 31, 32, 33, 34,
                               35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                               49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
                               63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
                               77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
                               91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103,
                               104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
                               115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
                               126, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137,
                               138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
                               149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
                               160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170,
                               171, 172, 173, 174, 175, 176, 178, 179, 180, 181, 182,
                               183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
                               194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204,
                               205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
                               216, 217, 218, 219, 220, 221, 222, 223])
        return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def get_evasion_headers(self) -> Dict[str, str]:
        """Return a dict of randomized WAF evasion headers.

        A random subset of WAF_EVASION_HEADERS is populated so that each
        request looks different while still bypassing common IP-based rules.
        """
        headers: Dict[str, str] = {}
        ip = self._random_ip()

        # Always include the most effective ones
        headers["X-Forwarded-For"] = ip
        headers["X-Originating-IP"] = ip
        headers["X-Remote-IP"] = ip

        # Randomly include additional headers
        extras = [h for h in self.WAF_EVASION_HEADERS if h not in headers]
        for header in random.sample(extras, k=min(random.randint(1, 4), len(extras))):
            if "Host" in header:
                headers[header] = f"localhost"
            elif "Proto" in header:
                headers[header] = "https"
            elif "URL" in header:
                headers[header] = "/"
            else:
                headers[header] = ip

        return headers

    @staticmethod
    def should_backoff(response: requests.Response) -> bool:
        """Return True if the response indicates we should back off (429 or CF 403)."""
        if response.status_code == 429:
            return True
        if response.status_code == 403:
            # Cloudflare-specific 403 detection
            cf_headers = response.headers.get("cf-ray") or response.headers.get("server", "")
            cf_body_markers = ["cloudflare", "cf-browser-verification", "Attention Required"]
            body_text = response.text[:2000].lower() if response.text else ""
            if "cloudflare" in cf_headers.lower() or any(m.lower() in body_text for m in cf_body_markers):
                return True
        return False

    @staticmethod
    def get_backoff_time(attempt: int) -> float:
        """Return exponential backoff time: min(2^attempt, 60) seconds."""
        return min(2 ** attempt, 60)


# ============================================================================
# RateLimiter  (token-bucket with jitter, improved from performance.py)
# ============================================================================


class RateLimiter:
    """Token-bucket rate limiter with random jitter for WAF evasion.

    Unlike the simple interval-based limiter in performance.py, this uses a
    proper token bucket that supports burst traffic and adds random jitter
    (0-200 ms) to make request timing less fingerprintable.
    """

    def __init__(self, rate: float = 15, burst: int = 20):
        """
        Args:
            rate: Tokens added per second (sustainable request rate).
            burst: Maximum tokens that can accumulate (peak burst capacity).
        """
        self.rate = rate
        self.burst = burst
        self._tokens: float = float(burst)
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()
        self._backoff_until: float = 0.0
        self._backoff_count: int = 0

    # -- internal helpers --------------------------------------------------

    def _refill(self) -> None:
        """Refill tokens based on elapsed time (must hold lock)."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_refill = now

    # -- public API --------------------------------------------------------

    def wait(self) -> None:
        """Block until a token is available, with random jitter (0-200 ms)."""
        with self._lock:
            # Respect explicit backoff first
            now = time.monotonic()
            if now < self._backoff_until:
                sleep_time = self._backoff_until - now
                # Release lock during sleep
                self._lock.release()
                try:
                    time.sleep(sleep_time)
                finally:
                    self._lock.acquire()
                self._last_refill = time.monotonic()

            self._refill()

            if self._tokens < 1.0:
                # Calculate how long until a token is available
                deficit = 1.0 - self._tokens
                wait_sec = deficit / self.rate
                # Add random jitter 0-200 ms
                jitter = random.uniform(0, 0.2)
                total_wait = wait_sec + jitter
                # Release lock during sleep
                self._lock.release()
                try:
                    time.sleep(total_wait)
                finally:
                    self._lock.acquire()
                self._refill()

            self._tokens -= 1.0

    def trigger_backoff(self, retry_after: Optional[float] = None) -> None:
        """Trigger exponential backoff (e.g., after 429 response).

        Args:
            retry_after: If the server sent Retry-After, use that value directly.
                         Otherwise, exponential backoff is calculated internally.
        """
        with self._lock:
            self._backoff_count += 1
            if retry_after is not None:
                self._backoff_until = time.monotonic() + float(retry_after)
            else:
                backoff_time = min(2 ** self._backoff_count, 60)
                self._backoff_until = time.monotonic() + backoff_time

    def reset_backoff(self) -> None:
        """Reset backoff counter after a successful request."""
        with self._lock:
            self._backoff_count = 0
            self._backoff_until = 0.0


# ============================================================================
# ThreadSafeSession  (fixes Bug #4)
# ============================================================================


class ThreadSafeSession(WAFEvasionMixin):
    """Thread-safe HTTP session with connection pooling, rate limiting, and
    WAF evasion.

    All session operations are guarded by a threading.Lock so that concurrent
    threads can safely share a single session instance.  User-Agent rotation,
    rate limiting, and exponential backoff on 429/CF-403 are built in.
    """

    def __init__(
        self,
        max_pool: int = 50,
        max_per_host: int = 10,
        rate_limit: float = 15,
        proxy: Optional[str] = None,
    ):
        super().__init__()
        self._lock = threading.Lock()

        # Underlying requests.Session with connection-pooling adapter
        self._session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=max_pool,
            pool_maxsize=max_pool,
            max_retries=2,
            pool_block=False,
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

        # Default session headers
        self._session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Connection": "keep-alive",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        })
        self._session.verify = VERIFY_SSL

        if proxy:
            self._session.proxies.update({"http": proxy, "https": proxy})

        # Rate limiter (token bucket with jitter)
        self._rate_limiter = RateLimiter(rate=rate_limit, burst=int(rate_limit * 1.3) + 1)

        # UA rotation tracking
        self._request_count: int = 0
        self._ua_rotate_every: int = 10

        # WAF evasion: inject evasion headers on every request
        self._evasion_enabled: bool = True

    # -- internal helpers --------------------------------------------------

    def _maybe_rotate_ua(self) -> None:
        """Rotate User-Agent every N requests. Must hold self._lock."""
        self._request_count += 1
        if self._request_count % self._ua_rotate_every == 0:
            self._session.headers["User-Agent"] = random.choice(USER_AGENTS)

    def _request_with_backoff(
        self,
        method: str,
        url: str,
        max_retries: int = 5,
        **kwargs: Any,
    ) -> requests.Response:
        """Core request method with rate limiting and exponential backoff.

        Must be called while self._lock is held by the caller.
        """
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        kwargs.setdefault("verify", VERIFY_SSL)
        kwargs.setdefault("allow_redirects", True)

        # Merge WAF evasion headers (do not overwrite caller-supplied headers)
        if self._evasion_enabled:
            evasion = self.get_evasion_headers()
            existing_headers = kwargs.get("headers", {})
            merged = {**evasion, **existing_headers}
            kwargs["headers"] = merged

        attempt = 0
        while True:
            # Rate limit
            self._lock.release()
            try:
                self._rate_limiter.wait()
            finally:
                self._lock.acquire()

            # Rotate UA if needed
            self._maybe_rotate_ua()

            try:
                response = self._session.request(method, url, **kwargs)

                # Check for 429 / CF 403
                if self.should_backoff(response) and attempt < max_retries:
                    attempt += 1
                    backoff = self.get_backoff_time(attempt)
                    # Respect Retry-After header if present
                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        try:
                            backoff = float(retry_after)
                        except ValueError:
                            pass
                    self._rate_limiter.trigger_backoff(retry_after=backoff)
                    continue

                # Successful request — reset backoff
                if response.status_code < 400:
                    self._rate_limiter.reset_backoff()

                return response

            except requests.exceptions.RequestException:
                attempt += 1
                if attempt >= max_retries:
                    raise
                backoff = self.get_backoff_time(attempt)
                self._lock.release()
                try:
                    time.sleep(backoff)
                finally:
                    self._lock.acquire()

    # -- public HTTP methods -----------------------------------------------

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        """Thread-safe GET request."""
        with self._lock:
            return self._request_with_backoff("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        """Thread-safe POST request."""
        with self._lock:
            return self._request_with_backoff("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        """Thread-safe PUT request."""
        with self._lock:
            return self._request_with_backoff("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        """Thread-safe DELETE request."""
        with self._lock:
            return self._request_with_backoff("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response:
        """Thread-safe HEAD request."""
        kwargs.setdefault("allow_redirects", False)
        with self._lock:
            return self._request_with_backoff("HEAD", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Thread-safe generic request."""
        with self._lock:
            return self._request_with_backoff(method, url, **kwargs)

    # -- utility -----------------------------------------------------------

    @property
    def cookies(self) -> requests.cookies.RequestsCookieJar:
        """Access session cookies (thread-safe read copy)."""
        with self._lock:
            return self._session.cookies.copy()

    def set_evasion(self, enabled: bool) -> None:
        """Enable or disable WAF evasion header injection."""
        with self._lock:
            self._evasion_enabled = enabled

    def close(self) -> None:
        """Close the underlying session."""
        with self._lock:
            self._session.close()


# ============================================================================
# OOBProvider  (fixes Improvement #4)
# ============================================================================


class OOBProvider:
    """Out-of-band callback provider — replaces hardcoded 127.0.0.1.

    Tries providers in order:
      1. interact.sh (cloud OOB with HTTP/DNS/SMTP interaction logging)
      2. dnslog.cn   (DNS-only OOB, widely accessible)
      3. local HTTP  (last resort — starts a tiny HTTP server on 8080)
    """

    def __init__(self):
        self.provider: Optional[str] = None
        self._domain: Optional[str] = None
        self._token: Optional[str] = None
        self._interactsh_url: str = "https://interactsh.com"
        self._local_port: int = 8080
        self._local_server: Optional[Any] = None
        self._local_thread: Optional[threading.Thread] = None
        self.interaction_log: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._initialized: bool = False

    # -- public API --------------------------------------------------------

    def initialize(self) -> bool:
        """Try OOB providers in order. Returns True on success."""
        if self._try_interactsh():
            return True
        if self._try_dnslog():
            return True
        self._fallback_local()
        return True  # local always "succeeds"

    def generate_payload_id(self) -> str:
        """Return a UUID-based payload identifier."""
        return uuid.uuid4().hex[:16]

    def get_callback_url(self, payload_id: str) -> str:
        """Return the full OOB callback URL for the given payload_id."""
        with self._lock:
            if not self._initialized:
                self.initialize()
            if self.provider == "interactsh" and self._domain:
                return f"http://{payload_id}.{self._domain}"
            elif self.provider == "dnslog" and self._domain:
                return f"http://{payload_id}.{self._domain}"
            else:
                return f"http://127.0.0.1:{self._local_port}/{payload_id}"

    def get_callback_domain(self, payload_id: str) -> str:
        """Return just the domain (for DNS-based OOB)."""
        with self._lock:
            if not self._initialized:
                self.initialize()
            if self.provider == "interactsh" and self._domain:
                return f"{payload_id}.{self._domain}"
            elif self.provider == "dnslog" and self._domain:
                return f"{payload_id}.{self._domain}"
            else:
                return f"127.0.0.1"

    def check_interactions(self, payload_id: str) -> List[Dict[str, Any]]:
        """Poll the OOB provider for interactions matching payload_id."""
        with self._lock:
            if not self._initialized:
                self.initialize()

        results: List[Dict[str, Any]] = []

        if self.provider == "interactsh":
            results = self._poll_interactsh(payload_id)
        elif self.provider == "dnslog":
            results = self._poll_dnslog(payload_id)
        else:
            results = self._poll_local(payload_id)

        self.interaction_log.extend(results)
        return results

    # -- interact.sh -------------------------------------------------------

    def _try_interactsh(self) -> bool:
        """Register with interact.sh to obtain a subdomain."""
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler

            # Generate a random correlation ID / secret
            corr_id = uuid.uuid4().hex
            secret = uuid.uuid4().hex

            register_data = {
                "correlation-id": corr_id,
                "secret": secret,
            }

            resp = requests.post(
                f"{self._interactsh_url}/register",
                json=register_data,
                timeout=10,
                verify=False,
            )

            if resp.status_code == 200:
                data = resp.json()
                # interact.sh returns the subdomain in different possible fields
                domain = data.get("subdomain") or data.get("domain") or data.get("address", "")
                if domain:
                    with self._lock:
                        self.provider = "interactsh"
                        self._domain = domain
                        self._token = secret
                        self._corr_id = corr_id
                        self._initialized = True
                    return True
        except Exception:
            pass
        return False

    def _poll_interactsh(self, payload_id: str) -> List[Dict[str, Any]]:
        """Poll interact.sh for interactions."""
        results: List[Dict[str, Any]] = []
        try:
            with self._lock:
                token = self._token
                corr_id = getattr(self, "_corr_id", "")

            resp = requests.get(
                f"{self._interactsh_url}/poll?id={corr_id}",
                headers={"Authorization": token or ""},
                timeout=10,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                interactions = data if isinstance(data, list) else data.get("data", data.get("interactions", []))
                for interaction in interactions:
                    if isinstance(interaction, dict):
                        full_id = interaction.get("full-id", "") or interaction.get("subdomain", "")
                        if payload_id in str(full_id):
                            results.append({
                                "provider": "interactsh",
                                "payload_id": payload_id,
                                "type": interaction.get("protocol", "unknown"),
                                "remote_address": interaction.get("remote-address", ""),
                                "raw_request": interaction.get("raw-request", ""),
                                "raw_response": interaction.get("raw-response", ""),
                                "timestamp": interaction.get("timestamp", ""),
                            })
        except Exception:
            pass
        return results

    # -- dnslog.cn ---------------------------------------------------------

    def _try_dnslog(self) -> bool:
        """Obtain a DNS log domain from dnslog.cn."""
        try:
            resp = requests.get(
                "http://www.dnslog.cn/getdomain.php",
                timeout=10,
                verify=False,
            )
            if resp.status_code == 200 and resp.text.strip():
                domain = resp.text.strip()
                if "." in domain:
                    with self._lock:
                        self.provider = "dnslog"
                        self._domain = domain
                        self._token = domain
                        self._initialized = True
                    return True
        except Exception:
            pass
        return False

    def _poll_dnslog(self, payload_id: str) -> List[Dict[str, Any]]:
        """Poll dnslog.cn for DNS interaction records."""
        results: List[Dict[str, Any]] = []
        try:
            with self._lock:
                domain = self._domain

            resp = requests.get(
                f"http://www.dnslog.cn/getrecords.php?id={domain}",
                timeout=10,
                verify=False,
            )
            if resp.status_code == 200:
                text = resp.text.strip()
                if text:
                    # dnslog.cn returns one domain per line
                    for line in text.splitlines():
                        if payload_id in line:
                            results.append({
                                "provider": "dnslog",
                                "payload_id": payload_id,
                                "type": "dns",
                                "subdomain": line.strip(),
                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            })
        except Exception:
            pass
        return results

    # -- local fallback ----------------------------------------------------

    def _fallback_local(self) -> None:
        """Last resort: start a local HTTP server on 8080."""
        from http.server import HTTPServer, BaseHTTPRequestHandler

        provider_self = self

        class _LocalHandler(BaseHTTPRequestHandler):
            """Minimal handler that logs all requests."""

            def do_GET(self):
                with provider_self._lock:
                    provider_self.interaction_log.append({
                        "provider": "local",
                        "payload_id": self.path.lstrip("/").split("?")[0].split("/")[0],
                        "type": "http",
                        "remote_address": self.client_address[0],
                        "path": self.path,
                        "headers": dict(self.headers),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    })
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""
                with provider_self._lock:
                    provider_self.interaction_log.append({
                        "provider": "local",
                        "payload_id": self.path.lstrip("/").split("?")[0].split("/")[0],
                        "type": "http",
                        "remote_address": self.client_address[0],
                        "path": self.path,
                        "body": body.decode("utf-8", errors="replace")[:2048],
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    })
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass  # Suppress stderr output

        try:
            server = HTTPServer(("0.0.0.0", self._local_port), _LocalHandler)
            server.timeout = 0.5
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            with self._lock:
                self.provider = "local"
                self._local_server = server
                self._local_thread = t
                self._initialized = True
        except OSError:
            # Port 8080 already in use — still mark as initialized
            with self._lock:
                self.provider = "local"
                self._initialized = True

    def _poll_local(self, payload_id: str) -> List[Dict[str, Any]]:
        """Return local interactions matching payload_id."""
        results: List[Dict[str, Any]] = []
        with self._lock:
            for entry in self.interaction_log:
                if entry.get("payload_id") == payload_id:
                    results.append(entry)
        return results


# ============================================================================
# RegexCache  (fixes Improvement #5)
# ============================================================================


class RegexCache:
    """Pre-compiled regex cache shared across all engines.

    Singleton pattern — every ``RegexCache()`` call returns the same instance.
    Common patterns used across 40+ engines are pre-compiled on first access.
    """

    _instance: Optional["RegexCache"] = None

    # Pre-compile common patterns used across the toolkit
    COMMON_PATTERNS: Dict[str, str] = {
        "ipv4": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "private_ip": r"(?:(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168\.\d{1,3})\.\d{1,3})",
        "url": r"https?://[^\s<>\"']+",
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "jwt": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "api_key_generic": r"api[_-]?key\s*[:=]\s*[\"'][a-zA-Z0-9_-]{20,}[\"']",
        "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "db_conn": r"(?i)(?:mongodb|postgres|mysql|redis)://[^\s\"'<>]+",
        "version": r"[\d]+\.[\d]+(?:\.[\d]+)?",
    }

    def __new__(cls) -> "RegexCache":
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._cache: Dict[Tuple[str, int], re.Pattern] = {}
            instance._lock = threading.Lock()
            cls._instance = instance
            # Pre-compile common patterns
            for name, pattern in cls.COMMON_PATTERNS.items():
                key = (pattern, 0)
                instance._cache[key] = re.compile(pattern)
        return cls._instance

    def _resolve(self, pattern: str) -> str:
        """Resolve a shorthand name to its raw regex string."""
        return self.COMMON_PATTERNS.get(pattern, pattern)

    def compile(self, pattern: str, flags: int = 0) -> re.Pattern:
        """Return a cached compiled regex pattern.

        If *pattern* is a key in COMMON_PATTERNS (e.g. 'ipv4'), the
        corresponding regex string is resolved automatically.
        """
        raw = self._resolve(pattern)
        key = (raw, flags)
        with self._lock:
            if key not in self._cache:
                self._cache[key] = re.compile(raw, flags)
            return self._cache[key]

    def search(self, pattern: str, string: str, flags: int = 0) -> Optional[re.Match]:
        """Search using a cached compiled pattern."""
        compiled = self.compile(pattern, flags)
        return compiled.search(string)

    def findall(self, pattern: str, string: str, flags: int = 0) -> List[str]:
        """Find all matches using a cached compiled pattern."""
        compiled = self.compile(pattern, flags)
        return compiled.findall(string)

    def match(self, pattern: str, string: str, flags: int = 0) -> Optional[re.Match]:
        """Match using a cached compiled pattern."""
        compiled = self.compile(pattern, flags)
        return compiled.match(string)

    @property
    def cached_count(self) -> int:
        """Number of cached compiled patterns."""
        with self._lock:
            return len(self._cache)


# ============================================================================
# ModernFrameworkDiscovery  (fixes Improvement #6)
# ============================================================================


class ModernFrameworkDiscovery:
    """Discovers hidden API endpoints from modern SPA frameworks.

    Techniques:
      - Source map (.js.map) parsing for hidden endpoints
      - Next.js __NEXT_DATA__ extraction
      - Webpack manifest / chunk analysis
      - JavaScript route extraction (React Router, Vue Router, fetch/axios calls)
      - Swagger / OpenAPI spec discovery
    """

    def __init__(self, session: Optional[Any] = None):
        """
        Args:
            session: A ThreadSafeSession or requests.Session instance.
                     Falls back to a basic requests.Session if None.
        """
        self.session = session
        self.discovered_endpoints: List[str] = []
        self.discovered_routes: List[str] = []

    # -- internal helper ---------------------------------------------------

    def _safe_get(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        """Make a GET request using the configured session, ignoring errors."""
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        kwargs.setdefault("verify", VERIFY_SSL)
        kwargs.setdefault("allow_redirects", True)
        try:
            if self.session is not None:
                return self.session.get(url, **kwargs)
            return requests.get(url, **kwargs)
        except Exception:
            return None

    # -- public API --------------------------------------------------------

    def discover(self, base_url: str) -> Dict[str, List[str]]:
        """Run all discovery techniques against *base_url*.

        Returns a dict keyed by technique name, each value being a deduplicated
        list of discovered endpoint paths.
        """
        results: Dict[str, List[str]] = {
            "js_maps": self.parse_source_maps(base_url),
            "next_data": self.extract_next_data(base_url),
            "webpack_manifest": self.parse_webpack_manifest(base_url),
            "js_routes": self.extract_js_routes(base_url),
            "swagger": self.check_swagger(base_url),
        }

        # Flatten and deduplicate
        all_endpoints: List[str] = []
        for endpoints in results.values():
            all_endpoints.extend(endpoints)

        seen: set = set()
        deduped: List[str] = []
        for ep in all_endpoints:
            if ep not in seen:
                seen.add(ep)
                deduped.append(ep)

        self.discovered_endpoints = deduped
        return results

    # -- technique implementations -----------------------------------------

    def parse_source_maps(self, base_url: str) -> List[str]:
        """Fetch and parse .js.map files for hidden endpoints."""
        endpoints: List[str] = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Common source map paths
        source_map_paths = [
            "/static/js/main.js.map",
            "/static/js/app.js.map",
            "/static/js/bundle.js.map",
            "/static/js/vendor.js.map",
            "/static/js/chunk.js.map",
            "/assets/main.js.map",
            "/assets/app.js.map",
            "/assets/bundle.js.map",
            "/js/main.js.map",
            "/js/app.js.map",
            "/dist/main.js.map",
            "/dist/app.js.map",
        ]

        # Also try Next.js specific paths
        # First, get the page HTML to find actual JS file URLs
        page_resp = self._safe_get(base_url)
        if page_resp and page_resp.status_code == 200:
            # Find .js file references
            js_pattern = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']*\.js)["\']', re.IGNORECASE)
            js_files = js_pattern.findall(page_resp.text)
            for js_file in js_files:
                if js_file.startswith("/"):
                    source_map_paths.append(js_file + ".map")
                elif js_file.startswith("http"):
                    source_map_paths.append(js_file + ".map")

            # Find _next specific paths
            next_js_pattern = re.compile(r'/_next/static/[^\s"\'<>]+\.js', re.IGNORECASE)
            next_js_files = next_js_pattern.findall(page_resp.text)
            for js_file in next_js_files:
                source_map_paths.append(js_file + ".map")

        for path in source_map_paths:
            if path.startswith("http"):
                map_url = path
            else:
                map_url = origin + path

            resp = self._safe_get(map_url)
            if resp and resp.status_code == 200:
                try:
                    source_map = resp.json()
                    # Extract from "sources" array
                    sources = source_map.get("sources", [])
                    for source in sources:
                        # Source paths often contain API routes
                        api_matches = re.findall(r'(/api/[^\s"\'<>?,]+)', str(source))
                        endpoints.extend(api_matches)
                        # Also look for route-like paths
                        route_matches = re.findall(r'(/[a-zA-Z][a-zA-Z0-9_\-/]*(?:/[a-zA-Z][a-zA-Z0-9_\-/]*)+)', str(source))
                        endpoints.extend(route_matches)

                    # Extract from "srcMap" if present
                    src_map = source_map.get("srcMap", source_map.get("srcContent", ""))
                    if isinstance(src_map, str):
                        api_matches = re.findall(r'(/api/[^\s"\'<>?,]+)', src_map)
                        endpoints.extend(api_matches)
                except (json.JSONDecodeError, ValueError):
                    pass

        return list(set(endpoints))

    def extract_next_data(self, base_url: str) -> List[str]:
        """Extract __NEXT_DATA__ JSON from Next.js pages for routes and API endpoints."""
        endpoints: List[str] = []
        resp = self._safe_get(base_url)
        if not resp or resp.status_code != 200:
            return endpoints

        text = resp.text

        # Extract __NEXT_DATA__ JSON
        next_data_pattern = re.compile(
            r'<script\s+id="__NEXT_DATA__"\s+type="application/json"[^>]*>(.*?)</script>',
            re.DOTALL,
        )
        match = next_data_pattern.search(text)
        if match:
            try:
                data = json.loads(match.group(1))
                # Extract buildId
                build_id = data.get("buildId", "")

                # Extract page routes
                page = data.get("page", "")
                if page:
                    endpoints.append(page)

                # Extract dynamic routes from props
                props = data.get("props", {}).get("pageProps", {})
                self._extract_paths_from_json(props, endpoints)

                # Look for API paths in the entire data structure
                data_str = json.dumps(data)
                api_paths = re.findall(r'(/api/[^\s"\'<>?,\\]+)', data_str)
                endpoints.extend(api_paths)

            except (json.JSONDecodeError, ValueError):
                pass

        # Try to fetch buildManifest.js for route list
        if "__NEXT_DATA__" in text:
            parsed = urlparse(base_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"

            # Find _next/static paths
            build_id_match = re.search(r'/_next/static/([^/]+)/', text)
            if build_id_match:
                build_id = build_id_match.group(1)
                manifest_url = f"{origin}/_next/static/{build_id}/_buildManifest.js"
                manifest_resp = self._safe_get(manifest_url)
                if manifest_resp and manifest_resp.status_code == 200:
                    manifest_text = manifest_resp.text
                    # Extract route paths from build manifest
                    route_pattern = re.compile(r'["\'](/[^"\']*?)["\']', re.IGNORECASE)
                    routes = route_pattern.findall(manifest_text)
                    for route in routes:
                        if route.startswith("/") and not route.startswith("/_next"):
                            endpoints.append(route)

        return list(set(endpoints))

    def parse_webpack_manifest(self, base_url: str) -> List[str]:
        """Parse Webpack manifest and chunk files for route definitions."""
        endpoints: List[str] = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Common webpack manifest paths
        manifest_paths = [
            "/static/js/webpack-*.js",
            "/assets/manifest.json",
            "/webpack-manifest.json",
            "/asset-manifest.json",
            "/static/manifest.json",
            "/manifest.json",
        ]

        for pattern_path in manifest_paths:
            if "*" in pattern_path:
                # Wildcard: try to find JS files in the page first
                page_resp = self._safe_get(base_url)
                if page_resp and page_resp.status_code == 200:
                    prefix = pattern_path.replace("*", "")
                    js_matches = re.findall(
                        re.escape(prefix) + r'[a-zA-Z0-9_.\-]+\.js',
                        page_resp.text,
                    )
                    for js_match in js_matches:
                        if js_match.startswith("http"):
                            manifest_url = js_match
                        else:
                            manifest_url = origin + js_match
                        manifest_resp = self._safe_get(manifest_url)
                        if manifest_resp and manifest_resp.status_code == 200:
                            extracted = self._extract_routes_from_js(manifest_resp.text)
                            endpoints.extend(extracted)
            else:
                manifest_url = origin + pattern_path
                manifest_resp = self._safe_get(manifest_url)
                if manifest_resp and manifest_resp.status_code == 200:
                    try:
                        data = manifest_resp.json()
                        # Extract chunk names and paths
                        files = data.get("files", data)
                        if isinstance(files, dict):
                            for chunk_name, chunk_path in files.items():
                                if isinstance(chunk_path, str) and chunk_path.endswith(".js"):
                                    chunk_url = origin + chunk_path if chunk_path.startswith("/") else chunk_path
                                    chunk_resp = self._safe_get(chunk_url)
                                    if chunk_resp and chunk_resp.status_code == 200:
                                        extracted = self._extract_routes_from_js(chunk_resp.text)
                                        endpoints.extend(extracted)
                    except (json.JSONDecodeError, ValueError):
                        pass

        return list(set(endpoints))

    def extract_js_routes(self, base_url: str) -> List[str]:
        """Extract route definitions from JavaScript bundle files."""
        endpoints: List[str] = []
        resp = self._safe_get(base_url)
        if not resp or resp.status_code != 200:
            return endpoints

        text = resp.text
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Find all JS file URLs in the page
        js_urls: List[str] = []

        # <script src="...">
        js_pattern = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
        js_urls.extend(js_pattern.findall(text))

        # _next JS files
        next_pattern = re.compile(r'/_next/static/[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?', re.IGNORECASE)
        js_urls.extend(next_pattern.findall(text))

        # Deduplicate and limit to avoid too many requests
        seen_urls: set = set()
        unique_js: List[str] = []
        for url in js_urls:
            if url not in seen_urls:
                seen_urls.add(url)
                unique_js.append(url)
            if len(unique_js) >= 15:
                break

        for js_path in unique_js:
            if js_path.startswith("http"):
                js_url = js_path
            elif js_path.startswith("/"):
                js_url = origin + js_path
            else:
                continue

            js_resp = self._safe_get(js_url)
            if js_resp and js_resp.status_code == 200:
                extracted = self._extract_routes_from_js(js_resp.text)
                endpoints.extend(extracted)

        return list(set(endpoints))

    def check_swagger(self, base_url: str) -> List[str]:
        """Check for Swagger/OpenAPI endpoint definitions."""
        endpoints: List[str] = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        swagger_paths = [
            "/swagger.json",
            "/swagger/v1/swagger.json",
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/api-docs/json",
            "/v1/docs",
            "/v2/docs",
            "/api/swagger.json",
            "/api/openapi.json",
            "/api/v1/swagger.json",
            "/api/v1/openapi.json",
            "/swagger-ui/swagger.json",
            "/docs/swagger.json",
            "/docs/openapi.json",
            "/.well-known/openapi.json",
        ]

        for path in swagger_paths:
            url = origin + path
            resp = self._safe_get(url)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    # OpenAPI 3.x
                    paths = data.get("paths", {})
                    for route_path in paths:
                        if route_path.startswith("/"):
                            endpoints.append(route_path)
                    # Swagger 2.x
                    paths = data.get("paths", {})
                    for route_path in paths:
                        if route_path.startswith("/") and route_path not in endpoints:
                            endpoints.append(route_path)
                    # Also look for basePath
                    base_path = data.get("basePath", "")
                    if base_path and base_path not in endpoints:
                        endpoints.append(base_path)
                except (json.JSONDecodeError, ValueError):
                    # Might be YAML or HTML — try route pattern extraction
                    api_paths = re.findall(r'(/api/[^\s"\'<>?,]+)', resp.text)
                    endpoints.extend(api_paths)

        return list(set(endpoints))

    # -- internal helpers --------------------------------------------------

    @staticmethod
    def _extract_routes_from_js(js_text: str) -> List[str]:
        """Extract route-like paths from JavaScript source text."""
        endpoints: List[str] = []

        # React Router: path: "/...", path: '...'
        react_routes = re.findall(r"""path\s*:\s*["'](/[^"']+)["']""", js_text)
        endpoints.extend(react_routes)

        # Vue Router: path: "/...", route: "..."
        vue_routes = re.findall(r"""(?:path|route)\s*:\s*["'](/[^"']+)["']""", js_text)
        endpoints.extend(vue_routes)

        # fetch("/api/...", axios.get("/api/...", axios.post("/api/..."
        fetch_routes = re.findall(
            r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|axios)\s*\(\s*["']([^"']*(?:/api/|/v\d/)[^"']*)["']""",
            js_text,
        )
        endpoints.extend(fetch_routes)

        # fetch(`/api/...`, axios.get(`/api/...`  (template literals)
        template_routes = re.findall(
            r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*`([^`]*(?:/api/|/v\d/)[^`]*)`""",
            js_text,
        )
        endpoints.extend(template_routes)

        # Generic /api/ path patterns
        generic_api = re.findall(r'(/api/[a-zA-Z0-9_\-/]+)', js_text)
        endpoints.extend(generic_api)

        # /v1/, /v2/ etc path patterns
        versioned_api = re.findall(r'(/v\d+/[a-zA-Z0-9_\-/]+)', js_text)
        endpoints.extend(versioned_api)

        return list(set(endpoints))

    @staticmethod
    def _extract_paths_from_json(obj: Any, endpoints: List[str], depth: int = 0) -> None:
        """Recursively extract path-like strings from JSON data."""
        if depth > 8:
            return
        if isinstance(obj, str):
            if obj.startswith("/") and len(obj) > 1 and not obj.startswith("//"):
                # Looks like a route path
                if re.match(r'^/[a-zA-Z0-9_\-/.:]*$', obj):
                    endpoints.append(obj)
        elif isinstance(obj, dict):
            for key, value in obj.items():
                if key in ("api", "endpoint", "url", "path", "route", "href"):
                    if isinstance(value, str) and value.startswith("/"):
                        endpoints.append(value)
                ModernFrameworkDiscovery._extract_paths_from_json(value, endpoints, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                ModernFrameworkDiscovery._extract_paths_from_json(item, endpoints, depth + 1)


# ============================================================================
# PayloadInjector  (fixes Improvement #2)
# ============================================================================


class PayloadInjector:
    """Modern payload injection into multiple contexts.

    Can be used in two ways:
      1. **Statically** — call static methods like ``PayloadInjector.inject_get()``
         which return dicts describing the injection context.
      2. **As an instance** — construct with a session, then call ``.inject()``
         which both builds the injection AND sends the request, returning the
         ``requests.Response`` object.
    """

    def __init__(self, session: Optional[Any] = None):
        """Initialize with an optional HTTP session for ``.inject()`` usage.

        Args:
            session: A ThreadSafeSession, requests.Session, or any object
                     with a ``.request()`` method.  Falls back to
                     ``shared_session`` if None.
        """
        self.session = session or shared_session

    def inject(
        self,
        url: str,
        param: str,
        payload: str,
        context: str = "all",
        **kwargs: Any,
    ) -> Optional[requests.Response]:
        """Build an injection and send it, returning the response.

        Args:
            url: Target URL.
            param: Parameter name to inject into.
            payload: Payload value.
            context: Injection context — ``'get'``, ``'post'``,
                     ``'json'``, ``'header'``, or ``'all'`` (tries GET
                     first, then POST, then JSON, then header).
            **kwargs: Extra keyword args forwarded to ``session.request()``.

        Returns:
            The first successful ``requests.Response``, or ``None`` on error.
        """
        context_map: Dict[str, Callable[..., Dict[str, Any]]] = {
            "get": PayloadInjector.inject_get,
            "post": PayloadInjector.inject_post_form,
            "json": PayloadInjector.inject_json,
            "header": lambda u, p, v: PayloadInjector.inject_header(u, "User-Agent", v),
        }

        if context == "all":
            # Try each context in order; return first that doesn't error
            for ctx_name in ("get", "post", "json", "header"):
                try:
                    builder = context_map[ctx_name]
                    injection = builder(url, param, payload)
                    resp = self._send_injection(injection, **kwargs)
                    if resp is not None:
                        return resp
                except Exception:
                    continue
            return None

        builder = context_map.get(context, PayloadInjector.inject_get)
        injection = builder(url, param, payload)
        return self._send_injection(injection, **kwargs)

    def _send_injection(
        self, injection: Dict[str, Any], **kwargs: Any
    ) -> Optional[requests.Response]:
        """Dispatch a prepared injection dict through the session."""
        url = injection.pop("url")
        method = injection.pop("method", "GET")
        # Merge any extra kwargs from the injection dict
        merged = {**injection, **kwargs}
        merged.setdefault("verify", VERIFY_SSL)
        merged.setdefault("timeout", DEFAULT_TIMEOUT)
        merged.setdefault("allow_redirects", True)
        try:
            return self.session.request(method, url, **merged)
        except requests.exceptions.RequestException:
            return None

    @staticmethod
    def inject_get(url: str, param: str, payload: str) -> Dict[str, Any]:
        """Inject payload into URL query parameter.

        Returns:
            Dict with ``url``, ``method``, and ``params`` keys.
        """
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        return {
            "url": new_url,
            "method": "GET",
            "params": {param: payload},
        }

    @staticmethod
    def inject_post_form(url: str, param: str, payload: str) -> Dict[str, Any]:
        """Inject payload into POST form data.

        Returns:
            Dict with ``url``, ``method``, and ``data`` keys.
        """
        return {
            "url": url,
            "method": "POST",
            "data": {param: payload},
        }

    @staticmethod
    def inject_json(url: str, param: str, payload: str, method: str = "POST") -> Dict[str, Any]:
        """Inject payload into JSON REST API body.

        Returns:
            Dict with ``url``, ``method``, ``json``, and ``headers`` keys.
        """
        return {
            "url": url,
            "method": method,
            "json": {param: payload},
            "headers": {"Content-Type": "application/json"},
        }

    @staticmethod
    def inject_xml(url: str, param: str, payload: str, xpath: Optional[str] = None) -> Dict[str, Any]:
        """Inject payload into XML node or attribute.

        If *xpath* is given, the payload is placed in an attribute at that path.
        Otherwise, it is placed as the text content of a node named *param*.

        Returns:
            Dict with ``url``, ``method``, ``data``, and ``headers`` keys.
        """
        if xpath:
            # Place payload in an attribute
            xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<root>
  <{xpath.split('/')[-1]} {param}="{payload}"/>
</root>"""
        else:
            xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<root>
  <{param}>{payload}</{param}>
</root>"""
        return {
            "url": url,
            "method": "POST",
            "data": xml,
            "headers": {"Content-Type": "application/xml"},
        }

    @staticmethod
    def inject_header(url: str, header_name: str, payload: str) -> Dict[str, Any]:
        """Inject payload into HTTP headers.

        Common targets: User-Agent, Referer, X-Forwarded-For, X-Original-URL,
        Cookie, Accept-Language.

        Returns:
            Dict with ``url``, ``method``, and ``headers`` keys.
        """
        return {
            "url": url,
            "method": "GET",
            "headers": {header_name: payload},
        }

    @staticmethod
    def inject_multipart(
        url: str,
        field_name: str,
        payload: str,
        filename: str = "test.txt",
    ) -> Dict[str, Any]:
        """Inject payload into multipart form upload.

        Returns:
            Dict with ``url``, ``method``, and ``files`` keys.
        """
        return {
            "url": url,
            "method": "POST",
            "files": {field_name: (filename, payload)},
        }

    @staticmethod
    def inject_all(url: str, param: str, payload: str) -> List[Dict[str, Any]]:
        """Inject payload into ALL contexts: GET, POST form, JSON, common headers.

        Returns:
            List of injection dicts, one per context.
        """
        injections: List[Dict[str, Any]] = [
            PayloadInjector.inject_get(url, param, payload),
            PayloadInjector.inject_post_form(url, param, payload),
            PayloadInjector.inject_json(url, param, payload),
            PayloadInjector.inject_header(url, "User-Agent", payload),
            PayloadInjector.inject_header(url, "Referer", payload),
            PayloadInjector.inject_header(url, "X-Forwarded-For", payload),
            PayloadInjector.inject_header(url, "X-Original-URL", payload),
            PayloadInjector.inject_header(url, "Cookie", f"{param}={payload}"),
        ]
        return injections


# ============================================================================
# AsyncSession  (fixes Improvement #1)
# ============================================================================


class AsyncSession:
    """Async HTTP session using aiohttp for high-concurrency scanning.

    Features:
      - Semaphore-limited concurrency (default 50)
      - Token-bucket rate limiting (shared with sync session concept)
      - Automatic User-Agent rotation
      - Retry with exponential backoff on 429/5xx
      - Optional proxy support
    """

    def __init__(
        self,
        max_concurrent: int = 50,
        rate_limit: float = 15,
        proxy: Optional[str] = None,
    ):
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.proxy = proxy
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._request_count: int = 0
        self._ua_rotate_every: int = 10
        # Simple async rate limiter state
        self._min_interval: float = 1.0 / rate_limit if rate_limit > 0 else 0
        self._last_request_time: float = 0.0
        self._rate_lock = asyncio.Lock()
        # Session is created lazily (needs an event loop)
        self._session: Optional[Any] = None

    async def _ensure_session(self) -> Any:
        """Lazily create the aiohttp.ClientSession."""
        if self._session is None or self._session.closed:
            import aiohttp

            connector = aiohttp.TCPConnector(
                limit=self.max_concurrent,
                limit_per_host=10,
                ssl=VERIFY_SSL if not VERIFY_SSL else None,
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                headers={
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "*/*",
                    "Connection": "keep-alive",
                },
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            )
        return self._session

    async def _rate_wait(self) -> None:
        """Wait for rate limiter (async-safe)."""
        if self._min_interval <= 0:
            return
        async with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_request_time = time.monotonic()

    def _get_ua(self) -> str:
        """Get current or rotated User-Agent."""
        self._request_count += 1
        if self._request_count % self._ua_rotate_every == 0:
            return random.choice(USER_AGENTS)
        return USER_AGENTS[self._request_count % len(USER_AGENTS)]

    async def _do_request(
        self,
        method: str,
        url: str,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> Any:
        """Core async request with rate limiting and backoff."""
        import aiohttp

        session = await self._ensure_session()
        kwargs.setdefault("timeout", aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT))
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("ssl", VERIFY_SSL if not VERIFY_SSL else None)

        if self.proxy:
            kwargs.setdefault("proxy", self.proxy)

        attempt = 0
        while True:
            await self._rate_wait()

            # Rotate UA
            headers = kwargs.pop("headers", {})
            headers["User-Agent"] = self._get_ua()
            kwargs["headers"] = headers

            try:
                async with self._semaphore:
                    async with session.request(method, url, **kwargs) as response:
                        body = await response.read()
                        # Check for 429 / 5xx retry
                        if response.status in (429, 502, 503, 504) and attempt < max_retries:
                            attempt += 1
                            backoff = min(2 ** attempt, 60)
                            retry_after = response.headers.get("Retry-After")
                            if retry_after:
                                try:
                                    backoff = float(retry_after)
                                except ValueError:
                                    pass
                            await asyncio.sleep(backoff)
                            continue
                        return response, body

            except (aiohttp.ClientError, asyncio.TimeoutError):
                attempt += 1
                if attempt >= max_retries:
                    raise
                backoff = min(2 ** attempt, 60)
                await asyncio.sleep(backoff)

    async def get(self, url: str, **kwargs: Any) -> Tuple[Any, bytes]:
        """Async GET request."""
        return await self._do_request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Tuple[Any, bytes]:
        """Async POST request."""
        return await self._do_request("POST", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> Tuple[Any, bytes]:
        """Async generic request."""
        return await self._do_request(method, url, **kwargs)

    async def batch_request(
        self,
        urls: List[str],
        method: str = "GET",
        callback: Optional[Callable] = None,
        **kwargs: Any,
    ) -> List[Any]:
        """Execute multiple requests concurrently.

        Args:
            urls: List of URLs to request.
            method: HTTP method for all requests.
            callback: Optional callable(url, response, body) invoked per URL.
            **kwargs: Passed through to each request.

        Returns:
            List of (url, response, body) tuples.
        """
        results: List[Any] = []

        async def _fetch(url: str) -> Tuple[str, Any, bytes]:
            try:
                response, body = await self._do_request(method, url, **kwargs)
                if callback:
                    try:
                        callback(url, response, body)
                    except Exception:
                        pass
                return (url, response, body)
            except Exception as exc:
                return (url, None, str(exc).encode())

        tasks = [asyncio.create_task(_fetch(u)) for u in urls]
        results = await asyncio.gather(*tasks)
        return list(results)

    async def close(self) -> None:
        """Close the underlying aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


# ============================================================================
# Global Singleton Instances
# ============================================================================

# Thread-safe, connection-pooled, rate-limited shared session
shared_session = ThreadSafeSession()

# Singleton regex cache with pre-compiled common patterns
regex_cache = RegexCache()

# Singleton OOB provider (lazy-initialised on first use)
oob_provider = OOBProvider()

# Singleton framework discovery backed by the shared session
framework_discovery = ModernFrameworkDiscovery(session=shared_session)
