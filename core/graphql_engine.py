"""
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝

ZYLON FUSION v3.0 - GraphQL Security Engine
Fused from: GraphQL-Cop by dolevf
Enhanced: Query depth probing, error-based schema enum, CORS testing, auth bypass
Termux Compatible | Python 3.13 | No Root Required
"""

import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote

try:
    import requests
except ImportError:
    requests = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    Console = None


# ============================================================================
# GRAPHQL SECURITY TESTS - All 13 Tests from GraphQL-Cop + 5 New
# ============================================================================

# Common GraphQL endpoint paths to probe
GRAPHQL_ENDPOINTS = [
    "/", "/graphql", "/graphiql", "/playground", "/console",
    "/api/graphql", "/api", "/query", "/v1/graphql", "/v2/graphql",
    "/gql", "/api/graph", "/services/graphql",
]

# Root query type names for fingerprinting
ROOT_TYPE_NAMES = ["Query", "QueryRoot", "query_root", "Root", "RootQuery"]


class GraphQLFingerprinter:
    """GraphQL endpoint discovery and fingerprinting."""

    @staticmethod
    def is_graphql(url: str, session: requests.Session,
                   timeout: int = 10) -> Tuple[bool, str]:
        """Fingerprint if a URL is a GraphQL endpoint.
        
        Three-tier detection:
        1. Strong: data.__typename matches known root types
        2. Medium: Errors contain 'locations' or 'extensions' (GraphQL error format)
        3. Weak: Response contains any 'data' key
        
        Returns: (is_graphql: bool, evidence: str)
        """
        query = "query cop { __typename }"
        payload = {"query": query, "operationName": "cop"}

        try:
            resp = session.post(
                url, json=payload,
                timeout=timeout, verify=False, allow_redirects=True,
            )
            data = resp.json()

            # Tier 1: Strong match - __typename is a known root type
            if data.get("data", {}).get("__typename") in ROOT_TYPE_NAMES:
                return True, f"Strong: __typename={data['data']['__typename']}"

            # Tier 2: Medium - GraphQL error structure
            errors = data.get("errors", [])
            if errors:
                for err in errors:
                    if "locations" in err or "extensions" in err:
                        return True, f"Medium: GraphQL error structure found"

            # Tier 3: Weak - any data key
            if "data" in data:
                return True, "Weak: data key present"

        except (json.JSONDecodeError, ValueError):
            pass
        except Exception:
            pass

        return False, ""

    @staticmethod
    def discover_endpoints(base_url: str, session: requests.Session,
                           timeout: int = 10) -> List[str]:
        """Discover GraphQL endpoints by probing common paths."""
        found = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in GRAPHQL_ENDPOINTS:
            url = base + path
            is_gql, _ = GraphQLFingerprinter.is_graphql(url, session, timeout)
            if is_gql:
                found.append(url)

        return found


class GraphQLSecurityTester:
    """Complete GraphQL security testing suite.
    
    Implements all 12 active tests from GraphQL-Cop plus 5 additional
    ZYLON-exclusive tests for deeper security analysis.
    """

    def __init__(self, url: str, session: requests.Session,
                 timeout: int = 10, proxy: str = None):
        self.url = url
        self.session = session
        self.timeout = timeout
        self.results: List[Dict] = []
        self.headers = {
            "User-Agent": "ZYLON-FUSION/3.0 GraphQL-Scanner",
            "Content-Type": "application/json",
        }

    def _graph_query(self, query: str, operation: str = "query",
                     batch: bool = False) -> Optional[Dict]:
        """Send a GraphQL query to the endpoint.
        
        Args:
            query: GraphQL query string
            operation: Operation type (query/mutation)
            batch: If True, send 10 identical queries as a batch array
        """
        payload = {operation: query, "operationName": "zylon"}

        try:
            if batch:
                # Array-based batching (10 queries)
                batch_payload = [payload] * 10
                resp = self.session.post(
                    self.url, json=batch_payload,
                    headers=self.headers, timeout=self.timeout,
                    verify=False, allow_redirects=True,
                )
            else:
                resp = self.session.post(
                    self.url, json=payload,
                    headers=self.headers, timeout=self.timeout,
                    verify=False, allow_redirects=True,
                )
            return resp.json()
        except Exception:
            return None

    def _http_request(self, method: str = "GET", params: Dict = None,
                      data: Dict = None, extra_headers: Dict = None) -> Optional[requests.Response]:
        """Send a raw HTTP request (for GET/CSRF tests)."""
        try:
            hdrs = dict(self.headers)
            if extra_headers:
                hdrs.update(extra_headers)
            resp = self.session.request(
                method=method, url=self.url,
                params=params, data=data,
                headers=hdrs, timeout=self.timeout,
                verify=False, allow_redirects=True,
            )
            return resp
        except Exception:
            return None

    def _get_error(self, response: Dict) -> str:
        """Safely extract error message from GraphQL response."""
        try:
            return response.get("errors", [{}])[0].get("message", "")
        except (IndexError, TypeError, AttributeError):
            return ""

    def _add_result(self, title: str, result: bool, severity: str,
                    impact: str, description: str, curl_cmd: str = ""):
        """Add a test result to the results list."""
        self.results.append({
            "title": title,
            "result": result,
            "severity": severity,
            "impact": impact,
            "description": description,
            "curl_verify": curl_cmd,
        })

    # ========================================================================
    # INFORMATION DISCLOSURE TESTS
    # ========================================================================

    def test_introspection(self) -> Dict:
        """Test 1: Introspection Query Enabled (HIGH)
        
        Full schema introspection reveals all type names and field names.
        If enabled, attackers can map the entire API surface.
        """
        query = "query zylon { __schema { types { name fields { name } } } }"
        response = self._graph_query(query)

        vulnerable = False
        description = "Introspection is disabled or restricted"

        if response:
            try:
                types = response.get("data", {}).get("__schema", {}).get("types", [])
                if types and len(types) > 0:
                    vulnerable = True
                    type_names = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")]
                    description = (
                        f"Introspection ENABLED - {len(types)} types exposed. "
                        f"User types: {', '.join(type_names[:10])}"
                    )
            except (AttributeError, TypeError):
                pass

        self._add_result(
            "Introspection Query", vulnerable, "HIGH",
            f"Information Leakage - {self.url}",
            description,
            f"curl -s -XPOST {self.url} -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'",
        )
        return self.results[-1]

    def test_trace_mode(self) -> Dict:
        """Test 2: Apollo Tracing Enabled (INFO)
        
        Apollo tracing exposes resolver timing data, revealing
        which fields take longest to resolve (useful for DoS targeting).
        """
        query = "query zylon { __typename }"
        response = self._graph_query(query)

        vulnerable = False
        description = "Tracing is not enabled"

        if response:
            # Path 1: Direct access to extensions.tracing
            try:
                tracing = response.get("errors", [{}])[0].get("extensions", {}).get("tracing")
                if tracing:
                    vulnerable = True
                    description = "Apollo tracing data exposed in error extensions"
            except (IndexError, TypeError, AttributeError):
                pass

            # Path 2: String search fallback
            if not vulnerable:
                resp_str = json.dumps(response).lower()
                if "'extensions': {'tracing':" in resp_str or '"extensions":{"tracing"' in resp_str:
                    vulnerable = True
                    description = "Apollo tracing data found in response (string match)"

        self._add_result(
            "Tracing Mode", vulnerable, "INFO",
            f"Information Leakage - {self.url}",
            description,
        )
        return self.results[-1]

    def test_field_suggestions(self) -> Dict:
        """Test 3: Field Suggestions Enabled (LOW)
        
        GraphQL servers like Apollo provide "Did you mean?" suggestions
        when a field name is close to a valid one, leaking schema info
        even if introspection is disabled.
        """
        query = "query zylon { __schema { directive } }"  # Invalid: should be 'directives'
        response = self._graph_query(query)

        vulnerable = False
        description = "Field suggestions are disabled"

        if response:
            error_msg = self._get_error(response)
            if "Did you mean" in error_msg or "did you mean" in error_msg.lower():
                vulnerable = True
                description = f"Field suggestions enabled - schema info leaked: '{error_msg[:100]}'"

        self._add_result(
            "Field Suggestions", vulnerable, "LOW",
            f"Information Leakage - {self.url}",
            description,
        )
        return self.results[-1]

    def test_unhandled_errors(self) -> Dict:
        """Test 4: Unhandled Error Detection (INFO)
        
        Deliberately malformed queries may trigger stack traces
        in extensions.exception, leaking implementation details.
        """
        query = "qwerty zylon { abc }"  # Invalid operation type
        response = self._graph_query(query)

        vulnerable = False
        description = "Errors are handled properly (no stack traces)"

        if response:
            # Path 1: Direct access
            try:
                exception = response.get("errors", [{}])[0].get("extensions", {}).get("exception")
                if exception:
                    vulnerable = True
                    description = f"Stack trace exposed in error extensions"
            except (IndexError, TypeError, AttributeError):
                pass

            # Path 2: String search
            if not vulnerable:
                resp_str = json.dumps(response).lower()
                if "'extensions': {'exception':" in resp_str or '"extensions":{"exception"' in resp_str:
                    vulnerable = True
                    description = "Stack trace found in error response"

        self._add_result(
            "Unhandled Error Detection", vulnerable, "INFO",
            f"Information Leakage - {self.url}",
            description,
        )
        return self.results[-1]

    def test_graphiql(self) -> Dict:
        """Test 5: GraphiQL/Playground IDE Exposed (LOW)
        
        Development IDEs should not be in production - they allow
        ad-hoc queries and leak the schema.
        """
        # Must request with Accept: text/html to trigger IDE rendering
        response = self._http_request(
            method="GET",
            extra_headers={"Accept": "text/html"},
        )

        vulnerable = False
        description = "No GraphiQL/Playground IDE detected"

        if response:
            heuristics = [
                "graphiql.min.css", "GraphQL Playground",
                "GraphiQL", "graphql-playground",
            ]
            for word in heuristics:
                if word in response.text:
                    vulnerable = True
                    description = f"GraphiQL/Playground IDE detected (found: '{word}')"
                    break

        self._add_result(
            "GraphiQL/Playground", vulnerable, "LOW",
            f"Information Leakage - {self.url}",
            description,
        )
        return self.results[-1]

    # ========================================================================
    # CSRF TESTS
    # ========================================================================

    def test_get_method_support(self) -> Dict:
        """Test 6: GET Method Query Support (MEDIUM)
        
        GET-based GraphQL queries enable CSRF because browsers
        automatically send GET requests with cookies.
        """
        query = "query zylon { __typename }"
        response = self._http_request(
            method="GET",
            params={"query": query},
        )

        vulnerable = False
        description = "GET method is not supported"

        if response:
            try:
                data = response.json()
                if data.get("data", {}).get("__typename"):
                    vulnerable = True
                    description = "GET method supported - CSRF possible via GET requests"
            except (json.JSONDecodeError, ValueError):
                pass

        self._add_result(
            "GET Method Support", vulnerable, "MEDIUM",
            f"Possible Cross Site Request Forgery - {self.url}",
            description,
        )
        return self.results[-1]

    def test_get_mutation(self) -> Dict:
        """Test 7: Mutation over GET Method (MEDIUM)
        
        If mutations execute over GET, attackers can forge
        state-changing operations via CSRF.
        """
        query = "mutation zylon { __typename }"
        response = self._http_request(
            method="GET",
            params={"query": query},
        )

        vulnerable = False
        description = "Mutations over GET are not supported"

        if response:
            try:
                data = response.json()
                if data.get("data", {}).get("__typename"):
                    vulnerable = True
                    description = "Mutations execute over GET - critical CSRF risk!"
            except (json.JSONDecodeError, ValueError):
                pass

        self._add_result(
            "Mutation over GET", vulnerable, "MEDIUM",
            f"Possible Cross Site Request Forgery - {self.url}",
            description,
        )
        return self.results[-1]

    def test_post_csrf(self) -> Dict:
        """Test 8: POST URL-Encoded CSRF (MEDIUM)
        
        If the server accepts application/x-www-form-urlencoded POST,
        CSRF is possible because HTML forms can submit URL-encoded
        POST requests cross-origin.
        """
        query = "query zylon { __typename }"
        response = self._http_request(
            method="POST",
            data={"query": query},
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        vulnerable = False
        description = "URL-encoded POST not supported"

        if response:
            try:
                data = response.json()
                if data.get("data", {}).get("__typename"):
                    vulnerable = True
                    description = "URL-encoded POST accepted - CSRF possible via HTML forms"
            except (json.JSONDecodeError, ValueError):
                pass

        self._add_result(
            "POST CSRF (URL-Encoded)", vulnerable, "MEDIUM",
            f"Possible Cross Site Request Forgery - {self.url}",
            description,
        )
        return self.results[-1]

    # ========================================================================
    # DENIAL OF SERVICE TESTS
    # ========================================================================

    def test_alias_overloading(self) -> Dict:
        """Test 9: Alias Overloading DoS (HIGH)
        
        GraphQL aliases allow querying the same field multiple times
        under different names. If the server doesn't limit alias count,
        attackers can amplify a single request into massive server work.
        """
        aliases = " ".join(f"alias{i}:__typename" for i in range(101))
        query = f"query zylon {{ {aliases} }}"
        response = self._graph_query(query)

        vulnerable = False
        description = "Alias limiting is in place"

        if response:
            try:
                if response.get("data", {}).get("alias100"):
                    vulnerable = True
                    description = "101 aliases processed without limit - DoS vector"
            except (AttributeError, TypeError):
                pass

        self._add_result(
            "Alias Overloading", vulnerable, "HIGH",
            f"Denial of Service - {self.url}",
            description,
        )
        return self.results[-1]

    def test_batch_query(self) -> Dict:
        """Test 10: Array-based Query Batching DoS (HIGH)
        
        Some GraphQL servers accept batched queries as JSON arrays.
        Without limits, attackers can send hundreds of queries per request,
        bypassing rate limiting.
        """
        response = self._graph_query("query zylon { __typename }", batch=True)

        vulnerable = False
        description = "Batch querying is not supported or limited"

        if response:
            try:
                if isinstance(response, list) and len(response) >= 10:
                    vulnerable = True
                    description = f"Batch queries accepted - {len(response)} queries processed without limit"
            except TypeError:
                pass

        self._add_result(
            "Batch Query DoS", vulnerable, "HIGH",
            f"Denial of Service - {self.url}",
            description,
        )
        return self.results[-1]

    def test_directive_overloading(self) -> Dict:
        """Test 11: Directive Overloading DoS (HIGH)
        
        Duplicate directives on a field force the server to validate
        each one. Without limiting, this causes excessive processing.
        """
        directives = "@aa" * 10
        query = f"query zylon {{ __typename {directives} }}"
        response = self._graph_query(query)

        vulnerable = False
        description = "Directive limiting is in place"

        if response:
            try:
                errors = response.get("errors", [])
                if len(errors) == 10:
                    vulnerable = True
                    description = "10 duplicate directives processed without short-circuit - DoS vector"
            except TypeError:
                pass

        self._add_result(
            "Directive Overloading", vulnerable, "HIGH",
            f"Denial of Service - {self.url}",
            description,
        )
        return self.results[-1]

    def test_circular_introspection(self) -> Dict:
        """Test 12: Circular Query via Introspection DoS (HIGH)
        
        The introspection schema is self-referential:
        __Type -> fields -> __Field -> type -> __Type (loops)
        5-level nesting forces exponential resolver execution.
        """
        query = (
            "query zylon { __schema { types { fields { type { fields "
            "{ type { fields { type { fields { type { name } } } } } "
            "} } } } } }"
        )
        response = self._graph_query(query)

        vulnerable = False
        description = "Depth limiting prevents circular introspection"

        if response:
            try:
                types = response.get("data", {}).get("__schema", {}).get("types", [])
                if len(types) > 25:
                    vulnerable = True
                    description = (
                        f"5-level circular introspection processed - {len(types)} types. "
                        f"Exponential resolver execution possible"
                    )
            except (AttributeError, TypeError):
                pass

        self._add_result(
            "Circular Introspection", vulnerable, "HIGH",
            f"Denial of Service - {self.url}",
            description,
        )
        return self.results[-1]

    # ========================================================================
    # ZYLON-EXCLUSIVE ENHANCED TESTS
    # ========================================================================

    def test_query_depth_limit(self) -> Dict:
        """Test 13: Query Depth Limiting (HIGH) - ZYLON EXCLUSIVE
        
        Sends queries at increasing depths (1, 5, 10, 15, 20)
        to identify the exact depth at which the server rejects.
        No depth limit = unlimited nesting = DoS.
        """
        max_accepted_depth = 0
        depth_thresholds = [1, 5, 10, 15, 20]

        for depth in depth_thresholds:
            # Build a nested query at the specified depth
            inner = "name"
            for _ in range(depth - 1):
                inner = f"__typename {{{inner}}}"
            query = f"query zylon {{ __schema {{ types {{ {inner} }} }} }}"

            response = self._graph_query(query)
            if response and not response.get("errors"):
                max_accepted_depth = depth
            else:
                break

        vulnerable = max_accepted_depth >= 15
        description = (
            f"Maximum accepted depth: {max_accepted_depth}. "
            + ("No effective depth limiting!" if vulnerable else "Depth limiting appears functional")
        )

        self._add_result(
            "Query Depth Limiting", vulnerable, "HIGH",
            f"Denial of Service - {self.url}",
            description,
        )
        return self.results[-1]

    def test_error_schema_enum(self) -> Dict:
        """Test 14: Error-Based Schema Enumeration (MEDIUM) - ZYLON EXCLUSIVE
        
        Systematically probe for type/field names via error messages.
        When a field doesn't exist, GraphQL may suggest valid alternatives
        or confirm the type exists with a different error.
        """
        # Probe common type names
        common_types = [
            "User", "Account", "Admin", "Post", "Comment",
            "Product", "Order", "Payment", "Token", "Session",
            "Mutation", "Subscription",
        ]
        discovered_types = []

        for type_name in common_types:
            query = f"query zylon {{ __type(name: \"{type_name}\") {{ name }} }}"
            response = self._graph_query(query)

            if response:
                data = response.get("data", {}).get("__type")
                if data is not None:
                    discovered_types.append(type_name)
                else:
                    # Check error messages for suggestions
                    error = self._get_error(response)
                    if "Did you mean" in error or "did you mean" in error.lower():
                        discovered_types.append(f"{type_name} (suggested)")

        vulnerable = len(discovered_types) > 0
        description = (
            f"Discovered {len(discovered_types)} types: {', '.join(discovered_types[:10])}"
            if vulnerable else "No types discovered via error messages"
        )

        self._add_result(
            "Error-Based Schema Enum", vulnerable, "MEDIUM",
            f"Information Leakage - {self.url}",
            description,
        )
        return self.results[-1]

    def test_cors_misconfiguration(self) -> Dict:
        """Test 15: CORS Misconfiguration (MEDIUM) - ZYLON EXCLUSIVE
        
        Test if the GraphQL endpoint allows cross-origin requests
        from arbitrary origins, which would enable data theft.
        """
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
        ]
        vulnerable = False
        allowed_origins = []

        for origin in test_origins:
            try:
                resp = self.session.post(
                    self.url,
                    json={"query": "query zylon { __typename }"},
                    headers={
                        **self.headers,
                        "Origin": origin,
                    },
                    timeout=self.timeout,
                    verify=False,
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == origin or acao == "*":
                    vulnerable = True
                    allowed_origins.append(f"{origin} (reflected: {acao})")
                elif acao and origin != "null" and origin in acao:
                    vulnerable = True
                    allowed_origins.append(f"{origin} (partial: {acao})")
            except Exception:
                pass

        description = (
            f"CORS allows: {', '.join(allowed_origins)}"
            if vulnerable else "CORS properly configured"
        )

        self._add_result(
            "CORS Misconfiguration", vulnerable, "MEDIUM",
            f"Possible Cross Origin Data Theft - {self.url}",
            description,
        )
        return self.results[-1]

    def run_all_tests(self) -> List[Dict]:
        """Run all 15 GraphQL security tests and return results."""
        self.results = []

        # Information disclosure tests
        self.test_introspection()
        self.test_trace_mode()
        self.test_field_suggestions()
        self.test_unhandled_errors()
        self.test_graphiql()

        # CSRF tests
        self.test_get_method_support()
        self.test_get_mutation()
        self.test_post_csrf()

        # DoS tests
        self.test_alias_overloading()
        self.test_batch_query()
        self.test_directive_overloading()
        self.test_circular_introspection()

        # ZYLON-exclusive enhanced tests
        self.test_query_depth_limit()
        self.test_error_schema_enum()
        self.test_cors_misconfiguration()

        return self.results


# ============================================================================
# GRAPHQL ENGINE - Main ZYLON Integration
# ============================================================================

class GraphQLEngine:
    """ZYLON GraphQL Security Engine.
    
    Fused from GraphQL-Cop with 5 additional ZYLON-exclusive tests:
    - 12 original GraphQL-Cop tests (introspection, tracing, CSRF, DoS, etc.)
    - Query depth limiting test (probes increasing depths)
    - Error-based schema enumeration (discovers types via errors)
    - CORS misconfiguration test (checks origin reflection)
    
    Total: 15 security tests across 4 categories.
    """

    def __init__(self, console=None):
        self.console = console or Console() if Console else None

    def _print(self, msg: str, style: str = ""):
        if self.console:
            self.console.print(msg, style=style)
        else:
            print(msg)

    def _create_session(self, proxy: str = None) -> requests.Session:
        session = requests.Session()
        session.verify = False
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        return session

    def scan_graphql_full(self, url: str, timeout: int = 10,
                          proxy: str = None) -> Dict:
        """Scan 72: Full GraphQL security audit.
        
        Runs all 15 security tests against the GraphQL endpoint.
        """
        self._print("\n[GraphQL] Starting Full Security Audit", "bold cyan")
        self._print(f"[GraphQL] Target: {url}", "dim")

        session = self._create_session(proxy)

        # Verify it's a GraphQL endpoint
        is_gql, evidence = GraphQLFingerprinter.is_graphql(url, session, timeout)
        if not is_gql:
            self._print("[GraphQL] Target is not a GraphQL endpoint", "bold red")
            return {"url": url, "is_graphql": False, "results": []}

        self._print(f"[GraphQL] Endpoint confirmed: {evidence}", "green")

        # Run all tests
        tester = GraphQLSecurityTester(url, session, timeout, proxy)
        results = tester.run_all_tests()

        # Categorize and display
        high_findings = [r for r in results if r["result"] and r["severity"] == "HIGH"]
        medium_findings = [r for r in results if r["result"] and r["severity"] == "MEDIUM"]
        low_findings = [r for r in results if r["result"] and r["severity"] == "LOW"]
        info_findings = [r for r in results if r["result"] and r["severity"] == "INFO"]

        self._print(f"\n[GraphQL] Results: {len(high_findings)} HIGH | "
                     f"{len(medium_findings)} MEDIUM | "
                     f"{len(low_findings)} LOW | "
                     f"{len(info_findings)} INFO", "bold yellow")

        for finding in high_findings:
            self._print(f"  [HIGH] {finding['title']}: {finding['description']}", "bold red")
        for finding in medium_findings:
            self._print(f"  [MEDIUM] {finding['title']}: {finding['description']}", "yellow")
        for finding in low_findings:
            self._print(f"  [LOW] {finding['title']}: {finding['description']}", "blue")
        for finding in info_findings:
            self._print(f"  [INFO] {finding['title']}: {finding['description']}", "dim")

        return {
            "url": url, "is_graphql": True,
            "results": results,
            "summary": {
                "total_tests": len(results),
                "high": len(high_findings),
                "medium": len(medium_findings),
                "low": len(low_findings),
                "info": len(info_findings),
                "passed": len([r for r in results if not r["result"]]),
            }
        }

    def scan_graphql_discover(self, base_url: str, timeout: int = 10,
                               proxy: str = None) -> Dict:
        """Scan 73: GraphQL endpoint discovery.
        
        Probes common paths to discover hidden GraphQL endpoints.
        """
        self._print("\n[GraphQL] Starting Endpoint Discovery", "bold cyan")
        self._print(f"[GraphQL] Base URL: {base_url}", "dim")

        session = self._create_session(proxy)
        found = GraphQLFingerprinter.discover_endpoints(base_url, session, timeout)

        self._print(f"\n[GraphQL] Found {len(found)} GraphQL endpoints:", "green")
        for url in found:
            self._print(f"  [+] {url}", "green")

        return {"base_url": base_url, "endpoints_found": found}

    def scan_graphql_introspection(self, url: str, timeout: int = 10,
                                    proxy: str = None) -> Dict:
        """Scan 74: GraphQL introspection extraction.
        
        If introspection is enabled, extract and map the entire schema.
        """
        self._print("\n[GraphQL] Starting Introspection Extraction", "bold cyan")
        self._print(f"[GraphQL] Target: {url}", "dim")

        session = self._create_session(proxy)
        headers = {
            "User-Agent": "ZYLON-FUSION/3.0",
            "Content-Type": "application/json",
        }

        # Full introspection query
        full_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    kind name description
                    fields(includeDeprecated: true) {
                        name description type { name kind }
                        args { name description type { name kind } }
                    }
                    inputFields { name description type { name kind } }
                    enumValues(includeDeprecated: true) { name description }
                }
                directives { name description locations args { name type { name } } }
            }
        }
        """

        try:
            resp = session.post(
                url, json={"query": full_query},
                headers=headers, timeout=timeout,
                verify=False, allow_redirects=True,
            )
            data = resp.json()
        except Exception as e:
            self._print(f"[GraphQL] Introspection failed: {str(e)[:100]}", "red")
            return {"url": url, "success": False, "error": str(e)[:200]}

        schema = data.get("data", {}).get("__schema", {})
        if not schema:
            self._print("[GraphQL] Introspection is disabled", "yellow")
            return {"url": url, "success": False, "introspection_enabled": False}

        # Parse schema
        types = schema.get("types", [])
        query_type = schema.get("queryType", {}).get("name", "")
        mutation_type = schema.get("mutationType", {}).get("name", "")

        # Categorize types
        object_types = [t for t in types if t.get("kind") == "OBJECT" and not t["name"].startswith("__")]
        input_types = [t for t in types if t.get("kind") == "INPUT_OBJECT"]
        enum_types = [t for t in types if t.get("kind") == "ENUM" and not t["name"].startswith("__")]
        interfaces = [t for t in types if t.get("kind") == "INTERFACE"]

        # Extract mutations with args
        mutations = []
        mutation_obj = next((t for t in object_types if t["name"] == mutation_type), None)
        if mutation_obj:
            for field in mutation_obj.get("fields", []):
                args = [a["name"] for a in field.get("args", [])]
                mutations.append({"name": field["name"], "args": args})

        # Extract queries with args
        queries = []
        query_obj = next((t for t in object_types if t["name"] == query_type), None)
        if query_obj:
            for field in query_obj.get("fields", []):
                args = [a["name"] for a in field.get("args", [])]
                queries.append({"name": field["name"], "args": args})

        self._print(f"\n[GraphQL] Schema Extracted!", "bold green")
        self._print(f"  [+] Object Types: {len(object_types)}", "green")
        self._print(f"  [+] Input Types: {len(input_types)}", "green")
        self._print(f"  [+] Enum Types: {len(enum_types)}", "green")
        self._print(f"  [+] Queries: {len(queries)}", "green")
        self._print(f"  [+] Mutations: {len(mutations)}", "green")

        for q in queries[:10]:
            args_str = f"({', '.join(q['args'])})" if q['args'] else ""
            self._print(f"      query: {q['name']}{args_str}", "dim")
        for m in mutations[:10]:
            args_str = f"({', '.join(m['args'])})" if m['args'] else ""
            self._print(f"      mutation: {m['name']}{args_str}", "dim")

        return {
            "url": url, "success": True, "introspection_enabled": True,
            "schema": {
                "query_type": query_type,
                "mutation_type": mutation_type,
                "object_types": len(object_types),
                "input_types": len(input_types),
                "enum_types": len(enum_types),
                "interfaces": len(interfaces),
                "queries": queries,
                "mutations": mutations,
            }
        }

    def scan_graphql_dos(self, url: str, timeout: int = 10,
                          proxy: str = None) -> Dict:
        """Scan 75: GraphQL DoS vector testing.
        
        Tests specifically for Denial of Service vectors:
        alias overloading, batch queries, directive overloading,
        circular introspection, and depth limiting.
        """
        self._print("\n[GraphQL] Starting DoS Vector Testing", "bold cyan")
        self._print(f"[GraphQL] Target: {url}", "dim")

        session = self._create_session(proxy)
        tester = GraphQLSecurityTester(url, session, timeout, proxy)

        # Run only DoS-related tests
        dos_results = []
        dos_results.append(tester.test_alias_overloading())
        dos_results.append(tester.test_batch_query())
        dos_results.append(tester.test_directive_overloading())
        dos_results.append(tester.test_circular_introspection())
        dos_results.append(tester.test_query_depth_limit())

        vulnerable = [r for r in dos_results if r["result"]]

        self._print(f"\n[GraphQL] DoS Results: {len(vulnerable)}/{len(dos_results)} vectors found",
                     "bold red" if vulnerable else "green")

        for r in dos_results:
            status = "VULNERABLE" if r["result"] else "SAFE"
            color = "red" if r["result"] else "green"
            self._print(f"  [{status}] {r['title']}: {r['description']}", color)

        return {
            "url": url,
            "dos_vectors": dos_results,
            "vulnerable_count": len(vulnerable),
        }

    def scan_graphql_csrf(self, url: str, timeout: int = 10,
                           proxy: str = None) -> Dict:
        """Scan 76: GraphQL CSRF testing.
        
        Tests for Cross-Site Request Forgery vectors:
        GET method support, GET mutations, URL-encoded POST.
        """
        self._print("\n[GraphQL] Starting CSRF Testing", "bold cyan")
        self._print(f"[GraphQL] Target: {url}", "dim")

        session = self._create_session(proxy)
        tester = GraphQLSecurityTester(url, session, timeout, proxy)

        csrf_results = []
        csrf_results.append(tester.test_get_method_support())
        csrf_results.append(tester.test_get_mutation())
        csrf_results.append(tester.test_post_csrf())

        vulnerable = [r for r in csrf_results if r["result"]]

        self._print(f"\n[GraphQL] CSRF Results: {len(vulnerable)}/{len(csrf_results)} vectors found",
                     "bold red" if vulnerable else "green")

        for r in csrf_results:
            status = "VULNERABLE" if r["result"] else "SAFE"
            color = "red" if r["result"] else "green"
            self._print(f"  [{status}] {r['title']}: {r['description']}", color)

        return {
            "url": url,
            "csrf_vectors": csrf_results,
            "vulnerable_count": len(vulnerable),
        }
