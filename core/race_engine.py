"""
██████╗  █████╗ ███████╗███████╗██████╗  ██████╗ ██╗    ██╗
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗██║    ██║
██████╔╝███████║███████╗█████╗  ██████╔╝██║   ██║██║ █╗ ██║
██╔═══╝ ██╔══██║╚════██║██╔══╝  ██╔══██╗██║   ██║██║███╗██║
██║     ██║  ██║███████║███████╗██║  ██║╚██████╔╝╚███╔███╔╝
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝

ZYLON FUSION v3.0 - Race Condition Detection Engine
Fused from: Race-the-Web by TheHackerDev
Enhanced: Barrier-based simultaneous fire, timing analysis, semantic comparison
Termux Compatible | Python 3.13 | No Root Required
"""

import time
import hashlib
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

from core.shared_infra import shared_session

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    Console = None


# ============================================================================
# DATA STRUCTURES (Inspired by Race-the-Web Go structs)
# ============================================================================

@dataclass
class RaceRequest:
    """A single request specification for race condition testing."""
    method: str = "GET"
    url: str = ""
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = False
    name: str = ""


@dataclass
class RaceResponse:
    """Response data from a single race request."""
    status_code: int = 0
    body: str = ""
    content_length: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    elapsed: float = 0.0
    error: str = ""
    request_index: int = 0
    request_name: str = ""


@dataclass
class UniqueResponse:
    """A cluster of identical responses indicating no race condition,
    or the baseline response that most requests match."""
    status_code: int = 0
    body_hash: str = ""
    content_length: int = 0
    count: int = 0
    sample_body: str = ""
    request_indices: List[int] = field(default_factory=list)
    request_names: List[str] = field(default_factory=list)
    avg_elapsed: float = 0.0
    elapsed_times: List[float] = field(default_factory=list)


# ============================================================================
# BARRIER-BASED SIMULTANEOUS FIRE (Improvement over Race-the-Web)
# ============================================================================

class BarrierFire:
    """Synchronizes all threads to fire at the exact same instant.
    
    Improvement over Race-the-Web's naive goroutine spawning:
    Uses a threading.Barrier to ensure ALL requests hit the server
    within microseconds of each other, not milliseconds.
    """

    def __init__(self, num_threads: int):
        self.barrier = threading.Barrier(num_threads)
        self.results: List[RaceResponse] = []
        self.lock = threading.Lock()

    def wait_and_fire(self, request: RaceRequest, index: int,
                      session: requests.Session, timeout: int = 30):
        """Wait at barrier, then fire request simultaneously with all others."""
        try:
            # Wait for all threads to be ready
            self.barrier.wait()
        except threading.BrokenBarrierError:
            return

        # Fire the request
        start = time.time()
        response = RaceResponse(
            request_index=index,
            request_name=request.name,
        )

        try:
            req_headers = dict(request.headers)
            # Merge cookies into headers instead of session cookie jar (thread-safe)
            if request.cookies:
                cookie_header = '; '.join(f'{name}={value}' for name, value in request.cookies.items())
                if cookie_header:
                    req_headers['Cookie'] = cookie_header

            resp = session.request(
                method=request.method,
                url=request.url,
                data=request.body if request.method in ("POST", "PUT", "PATCH") else None,
                headers=req_headers,
                timeout=timeout,
                allow_redirects=request.follow_redirects,
                verify=False,
            )

            elapsed = time.time() - start
            response.status_code = resp.status_code
            response.body = resp.text
            response.content_length = len(resp.content)
            response.elapsed = elapsed
            response.headers = dict(resp.headers)

        except requests.exceptions.Timeout:
            response.error = "timeout"
            response.elapsed = time.time() - start
        except Exception as e:
            response.error = str(e)[:200]
            response.elapsed = time.time() - start

        with self.lock:
            self.results.append(response)


# ============================================================================
# RESPONSE COMPARISON ENGINE (Enhanced from Race-the-Web)
# ============================================================================

class ResponseComparator:
    """Compare and cluster race condition responses.
    
    Enhanced from Race-the-Web's triple-criterion comparison:
    - Exact match (original: status + body + content-length)
    - Semantic match (strips dynamic tokens like timestamps, CSRF)
    - Hash-based match (for O(1) lookup instead of O(n^2))
    """

    # Patterns for dynamic content that should be ignored in semantic comparison
    DYNAMIC_PATTERNS = [
        r'csrf[_-]?token["\s:=]+["\']?[a-zA-Z0-9_-]+',
        r'_token["\s:=]+["\']?[a-zA-Z0-9_-]+',
        r'nonce["\s:=]+["\']?[a-zA-Z0-9_-]+',
        r'timestamp["\s:=]+["\']?\d+',
        r'"id":\s*\d+',
        r'request[_-]?id["\s:=]+["\']?[a-zA-Z0-9_-]+',
        r'X-Request-Id:?\s*[a-zA-Z0-9-]+',
        r'Date:?\s*[^\r\n]+',
        r'X-Response-Time:?\s*[^\r\n]+',
    ]

    @staticmethod
    def body_hash(body: str, semantic: bool = False) -> str:
        """Generate hash of response body for comparison.
        
        Args:
            body: Response body text
            semantic: If True, strip dynamic content before hashing
        """
        content = body
        if semantic:
            import re
            for pattern in ResponseComparator.DYNAMIC_PATTERNS:
                content = re.sub(pattern, '', content, flags=re.IGNORECASE)
        return hashlib.md5(content.encode()).hexdigest()

    @staticmethod
    def cluster_responses(responses: List[RaceResponse],
                          semantic: bool = False) -> List[UniqueResponse]:
        """Cluster responses into unique groups for race condition detection.
        
        Uses hash-based comparison for O(1) lookup instead of O(n^2).
        
        Args:
            responses: List of race responses
            semantic: Use semantic comparison (strip dynamic content)
        """
        clusters: Dict[Tuple[int, str, int], UniqueResponse] = {}

        for resp in responses:
            if resp.error:
                continue

            bhash = ResponseComparator.body_hash(resp.body, semantic)
            key = (resp.status_code, bhash, resp.content_length)

            if key in clusters:
                cluster = clusters[key]
                cluster.count += 1
                cluster.request_indices.append(resp.request_index)
                if resp.request_name:
                    cluster.request_names.append(resp.request_name)
                cluster.elapsed_times.append(resp.elapsed)
                cluster.avg_elapsed = sum(cluster.elapsed_times) / len(cluster.elapsed_times)
            else:
                clusters[key] = UniqueResponse(
                    status_code=resp.status_code,
                    body_hash=bhash,
                    content_length=resp.content_length,
                    count=1,
                    sample_body=resp.body[:500],
                    request_indices=[resp.request_index],
                    request_names=[resp.request_name] if resp.request_name else [],
                    avg_elapsed=resp.elapsed,
                    elapsed_times=[resp.elapsed],
                )

        return sorted(clusters.values(), key=lambda c: c.count, reverse=True)


# ============================================================================
# RACE CONDITION DETECTOR
# ============================================================================

class RaceConditionDetector:
    """Main race condition detection engine.
    
    Uses barrier-based simultaneous fire to send concurrent requests,
    then clusters responses to detect race conditions.
    
    A race condition is detected when:
    - Multiple unique response clusters appear
    - The minority cluster(s) have different content than the majority
    - This indicates the server processed requests inconsistently
    """

    def __init__(self, timeout: int = 30, proxy: str = None,
                 max_workers: int = 200):
        self.timeout = timeout
        self.proxy = proxy
        self.max_workers = max_workers

    def _create_session(self):
        """Return the shared thread-safe session.

        Uses shared_session from core.shared_infra which provides
        thread-safe connection pooling, rate limiting, and WAF evasion.
        """
        return shared_session

    def detect_race_condition(self, request: RaceRequest,
                              count: int = 100,
                              semantic: bool = True) -> Dict:
        """Detect race condition on a single endpoint.
        
        Sends 'count' identical requests simultaneously using barrier-fire,
        then clusters responses to detect inconsistencies.
        
        Args:
            request: The request specification
            count: Number of concurrent requests to send
            semantic: Use semantic comparison for response clustering
        """
        results = {
            "url": request.url, "method": request.method,
            "count": count, "unique_clusters": [],
            "race_detected": False, "race_evidence": "",
            "timing": {}, "errors": 0,
        }

        # Create session and barrier
        session = self._create_session()
        barrier = BarrierFire(count)

        # Launch all threads
        threads = []
        for i in range(count):
            t = threading.Thread(
                target=barrier.wait_and_fire,
                args=(request, i, session, self.timeout),
                daemon=True,
            )
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join(timeout=self.timeout + 10)

        # Collect results
        responses = barrier.results
        results["errors"] = sum(1 for r in responses if r.error)

        # Cluster responses
        clusters = ResponseComparator.cluster_responses(responses, semantic)
        results["unique_clusters"] = [
            {
                "status_code": c.status_code,
                "body_hash": c.body_hash,
                "content_length": c.content_length,
                "count": c.count,
                "avg_elapsed": round(c.avg_elapsed, 4),
                "sample_body": c.sample_body[:200],
            }
            for c in clusters
        ]

        # Timing analysis
        if responses:
            elapsed_times = [r.elapsed for r in responses if not r.error]
            if elapsed_times:
                results["timing"] = {
                    "min": round(min(elapsed_times), 4),
                    "max": round(max(elapsed_times), 4),
                    "avg": round(sum(elapsed_times) / len(elapsed_times), 4),
                    "spread": round(max(elapsed_times) - min(elapsed_times), 4),
                }

        # Race condition detection logic
        # If there's more than 1 unique cluster, race condition is likely
        if len(clusters) > 1:
            majority = clusters[0]
            minorities = clusters[1:]

            # Race condition: minority responses differ from majority
            minority_count = sum(c.count for c in minorities)
            total = sum(c.count for c in clusters)

            if minority_count > 0 and total > 0:
                minority_ratio = minority_count / total
                results["race_detected"] = True
                results["race_evidence"] = (
                    f"{minority_count}/{total} requests ({minority_ratio:.1%}) "
                    f"returned different response than majority. "
                    f"Majority: status={majority.status_code}, "
                    f"len={majority.content_length}. "
                    f"Minority: status={minorities[0].status_code}, "
                    f"len={minorities[0].content_length}."
                )

        return results

    def detect_multi_endpoint_race(self, requests_list: List[RaceRequest],
                                    count: int = 50,
                                    semantic: bool = True) -> Dict:
        """Detect race conditions across multiple endpoints.
        
        Tests cross-endpoint race conditions by sending requests to
        different URLs simultaneously.
        
        Args:
            requests_list: List of request specifications
            count: Number of times to repeat the test
            semantic: Use semantic comparison for response clustering
        """
        results = {
            "endpoints": [r.url for r in requests_list],
            "passes": count,
            "race_detected": False,
            "inconsistencies": [],
        }

        session = self._create_session()
        total_requests = count * len(requests_list)

        for pass_num in range(count):
            barrier = BarrierFire(len(requests_list))
            threads = []

            for i, req in enumerate(requests_list):
                t = threading.Thread(
                    target=barrier.wait_and_fire,
                    args=(req, i, session, self.timeout),
                    daemon=True,
                )
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=self.timeout + 10)

            # Check for inconsistencies in this pass
            responses = [r for r in barrier.results if not r.error]
            if len(responses) >= 2:
                clusters = ResponseComparator.cluster_responses(responses, semantic)
                if len(clusters) > 1:
                    results["race_detected"] = True
                    results["inconsistencies"].append({
                        "pass": pass_num + 1,
                        "unique_responses": len(clusters),
                        "clusters": [
                            {
                                "status": c.status_code,
                                "count": c.count,
                                "url_indices": c.request_indices,
                            }
                            for c in clusters
                        ],
                    })

        return results

    def detect_toctou(self, read_request: RaceRequest,
                      write_request: RaceRequest,
                      count: int = 100,
                      semantic: bool = True) -> Dict:
        """Detect Time-Of-Check-Time-Of-Use (TOCTOU) race conditions.
        
        Sends read and write requests simultaneously to detect if
        the write operation can occur between the check and use.
        
        Args:
            read_request: The "check" request (e.g., balance inquiry)
            write_request: The "use" request (e.g., withdrawal)
            count: Number of concurrent request pairs
            semantic: Use semantic comparison
        """
        results = {
            "read_url": read_request.url,
            "write_url": write_request.url,
            "count": count,
            "race_detected": False,
            "toctou_evidence": "",
            "read_responses": [],
            "write_responses": [],
        }

        session = self._create_session()
        total = count * 2  # read + write for each iteration
        barrier = BarrierFire(total)
        threads = []

        for i in range(count):
            # Read request
            t_read = threading.Thread(
                target=barrier.wait_and_fire,
                args=(read_request, i, session, self.timeout),
                daemon=True,
            )
            threads.append(t_read)

            # Write request
            t_write = threading.Thread(
                target=barrier.wait_and_fire,
                args=(write_request, i + count, session, self.timeout),
                daemon=True,
            )
            threads.append(t_write)

        for t in threads:
            t.start()

        for t in threads:
            t.join(timeout=self.timeout + 10)

        # Separate read and write responses
        all_responses = barrier.results
        read_responses = [r for r in all_responses if r.request_index < count]
        write_responses = [r for r in all_responses if r.request_index >= count]

        # Cluster read responses
        read_clusters = ResponseComparator.cluster_responses(read_responses, semantic)
        write_clusters = ResponseComparator.cluster_responses(write_responses, semantic)

        results["read_responses"] = [
            {"status": c.status_code, "count": c.count, "body_sample": c.sample_body[:200]}
            for c in read_clusters
        ]
        results["write_responses"] = [
            {"status": c.status_code, "count": c.count, "body_sample": c.sample_body[:200]}
            for c in write_clusters
        ]

        # TOCTOU detection: if read responses differ, TOCTOU likely occurred
        if len(read_clusters) > 1:
            results["race_detected"] = True
            majority = read_clusters[0]
            minorities = read_clusters[1:]
            minority_count = sum(c.count for c in minorities)
            results["toctou_evidence"] = (
                f"TOCTOU detected: {minority_count}/{sum(c.count for c in read_clusters)} "
                f"read requests returned different data, indicating state changed "
                f"during concurrent operations. "
                f"Majority read: status={majority.status_code}, len={majority.content_length}. "
                f"Minority read: status={minorities[0].status_code}, len={minorities[0].content_length}."
            )

        return results


# ============================================================================
# RACE CONDITION ENGINE - Main ZYLON Integration
# ============================================================================

class RaceEngine:
    """ZYLON Race Condition Detection Engine.
    
    Fused from Race-the-Web with critical improvements:
    - Barrier-based simultaneous fire (vs naive goroutine spawning)
    - Semantic response comparison (strips dynamic tokens)
    - Hash-based clustering (O(1) vs O(n^2))
    - TOCTOU-specific detection mode
    - Multi-endpoint race testing
    - Timing analysis with spread measurement
    """

    def __init__(self, console=None):
        self.console = console or Console() if Console else None

    def _print(self, msg: str, style: str = ""):
        if self.console:
            self.console.print(msg, style=style)
        else:
            print(msg)

    def scan_race_single(self, url: str, method: str = "GET",
                         body: str = "", headers: Dict = None,
                         cookies: Dict = None, count: int = 100,
                         timeout: int = 30, proxy: str = None) -> Dict:
        """Scan 69: Single-endpoint race condition test.
        
        Sends 'count' identical requests simultaneously to detect
        if the server processes them inconsistently.
        """
        self._print("\n[RACE] Starting Single-Endpoint Race Condition Test", "bold cyan")
        self._print(f"[RACE] Target: {url} | Method: {method} | Count: {count}", "dim")

        request = RaceRequest(
            method=method, url=url, body=body,
            headers=headers or {}, cookies=cookies or {},
            name="race_test",
        )

        detector = RaceConditionDetector(timeout, proxy)
        results = detector.detect_race_condition(request, count)

        # Display results
        if results["race_detected"]:
            self._print("\n[RACE] RACE CONDITION DETECTED!", "bold red")
            self._print(f"  [+] {results['race_evidence']}", "red")
            self._print(f"  [+] Unique response clusters: {len(results['unique_clusters'])}", "yellow")
            for i, cluster in enumerate(results["unique_clusters"]):
                self._print(
                    f"      Cluster {i+1}: status={cluster['status_code']}, "
                    f"count={cluster['count']}, len={cluster['content_length']}",
                    "yellow" if i > 0 else "green",
                )
        else:
            self._print("\n[RACE] No race condition detected", "green")
            self._print(f"  All {count} requests returned identical responses", "dim")

        if results.get("timing"):
            t = results["timing"]
            self._print(f"  Timing: min={t['min']}s, max={t['max']}s, spread={t['spread']}s", "dim")

        return results

    def scan_race_multi(self, urls: List[str], method: str = "POST",
                        body: str = "", headers: Dict = None,
                        cookies: Dict = None, count: int = 50,
                        timeout: int = 30, proxy: str = None) -> Dict:
        """Scan 70: Multi-endpoint race condition test.
        
        Tests cross-endpoint race conditions by sending requests
        to different URLs simultaneously.
        """
        self._print("\n[RACE] Starting Multi-Endpoint Race Condition Test", "bold cyan")
        self._print(f"[RACE] Endpoints: {len(urls)} | Passes: {count}", "dim")

        requests_list = [
            RaceRequest(
                method=method, url=url, body=body,
                headers=headers or {}, cookies=cookies or {},
                name=f"endpoint_{i}",
            )
            for i, url in enumerate(urls)
        ]

        detector = RaceConditionDetector(timeout, proxy)
        results = detector.detect_multi_endpoint_race(requests_list, count)

        if results["race_detected"]:
            self._print("\n[RACE] CROSS-ENDPOINT RACE CONDITION DETECTED!", "bold red")
            for inc in results["inconsistencies"]:
                self._print(
                    f"  [+] Pass {inc['pass']}: {inc['unique_responses']} unique responses",
                    "red"
                )
        else:
            self._print("\n[RACE] No cross-endpoint race condition detected", "green")

        return results

    def scan_race_toctou(self, read_url: str, write_url: str,
                         read_method: str = "GET", write_method: str = "POST",
                         read_body: str = "", write_body: str = "",
                         headers: Dict = None, cookies: Dict = None,
                         count: int = 100, timeout: int = 30,
                         proxy: str = None) -> Dict:
        """Scan 71: TOCTOU (Time-Of-Check-Time-Of-Use) race condition test.
        
        Sends read (check) and write (use) requests simultaneously
        to detect if state changes between check and use operations.
        """
        self._print("\n[RACE] Starting TOCTOU Race Condition Test", "bold cyan")
        self._print(f"[RACE] Read: {read_url} | Write: {write_url} | Count: {count}", "dim")

        read_request = RaceRequest(
            method=read_method, url=read_url, body=read_body,
            headers=headers or {}, cookies=cookies or {},
            name="read_check",
        )
        write_request = RaceRequest(
            method=write_method, url=write_url, body=write_body,
            headers=headers or {}, cookies=cookies or {},
            name="write_use",
        )

        detector = RaceConditionDetector(timeout, proxy)
        results = detector.detect_toctou(read_request, write_request, count)

        if results["race_detected"]:
            self._print("\n[RACE] TOCTOU RACE CONDITION DETECTED!", "bold red")
            self._print(f"  [+] {results['toctou_evidence']}", "red")
            self._print(f"  [+] Read response clusters: {len(results['read_responses'])}", "yellow")
            self._print(f"  [+] Write response clusters: {len(results['write_responses'])}", "yellow")
        else:
            self._print("\n[RACE] No TOCTOU race condition detected", "green")
            self._print(f"  All read responses were consistent", "dim")

        return results
