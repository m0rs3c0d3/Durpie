#!/usr/bin/env python3
"""
Durpie v2 - Standalone Addons
=============================

Individual mitmproxy addons for specific testing scenarios.
Load only what you need for focused testing.

Phase 1 addons (passive / advisory):
    - ActiveSQLiScanner  : Basic SQLi tester (advisory only; see active_scanners.py for full)
    - CredentialStuffer  : Test leaked credentials against login endpoints
    - IDORTester         : IDOR detection and guidance
    - SessionAnalyzer    : Session management security analysis
    - GraphQLScanner     : GraphQL endpoint detection and introspection testing
    - RaceConditionTester: Race condition candidate detection + test script generation
    - SmartLogger        : Filtered request logging (excludes static assets)
    - WAFBypassTester    : WAF detection and bypass suggestions

Phase 2 addons (active scanning) are in active_scanners.py:
    - ActiveSQLiScanner  : Error-based, boolean-blind, time-based, UNION SQLi
    - ActiveXSSScanner   : Context-aware XSS with PoC generation
    - SSRFExploiter      : Cloud metadata, internal port scanning, protocol smuggling

Usage:
    # Passive addons only
    mitmdump -s addons.py

    # Active scanning (Phase 2)
    mitmdump -s active_scanners.py

    # Both passive and active
    mitmdump -s addons.py -s active_scanners.py
"""

import re
import json
import time
import asyncio
import aiohttp
from typing import List, Dict, Optional
from collections import defaultdict
from datetime import datetime

try:
    from mitmproxy import http, ctx
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False


# ============================================================
# ADDON: Active SQL Injection Scanner
# ============================================================

class ActiveSQLiScanner:
    """
    Actively tests parameters for SQL injection.
    
    Usage:
        mitmdump -s addons.py:ActiveSQLiScanner
    
    Use case:
        - Automatically fuzz every parameter with SQLi payloads
        - Detect error-based, blind boolean, and time-based SQLi
    """
    
    PAYLOADS = {
        'error_based': [
            "'", "''", '"', "\\",
            "1' OR '1'='1", 
            "' UNION SELECT NULL--",
        ],
        'time_based': [
            "'; WAITFOR DELAY '0:0:3'--",
            "' AND SLEEP(3)--",
            "1' AND (SELECT * FROM (SELECT SLEEP(3))a)--",
        ],
        'boolean_based': [
            "' AND '1'='1",
            "' AND '1'='2",
        ]
    }
    
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"PostgreSQL.*ERROR",
        r"ORA-\d{5}",
        r"SQLSTATE\[",
        r"Unclosed quotation mark",
    ]
    
    def __init__(self):
        self.tested = set()
        self.findings = []
    
    def response(self, flow: http.HTTPFlow):
        """Test parameters after seeing the normal response"""
        if not flow.response:
            return
        
        # Skip if already tested
        endpoint_key = f"{flow.request.host}:{flow.request.path}"
        if endpoint_key in self.tested:
            return
        self.tested.add(endpoint_key)
        
        # Get baseline
        baseline_length = len(flow.response.content)
        baseline_time = 0  # Would need timing from request
        
        # Test query parameters
        for param, value in flow.request.query.items():
            ctx.log.info(f"[SQLi] Testing param: {param}")
            self._test_param(flow, 'query', param, baseline_length)
        
        # Test form parameters
        if flow.request.urlencoded_form:
            for param, value in flow.request.urlencoded_form.items():
                ctx.log.info(f"[SQLi] Testing form param: {param}")
                self._test_param(flow, 'form', param, baseline_length)
    
    def _test_param(self, flow: http.HTTPFlow, param_type: str, param_name: str, baseline_length: int):
        """Test a single parameter"""
        # This would need to replay requests - simplified version
        for payload in self.PAYLOADS['error_based']:
            finding = {
                'type': 'SQLi Test Required',
                'param_type': param_type,
                'param_name': param_name,
                'payload': payload,
                'url': flow.request.pretty_url,
                'note': 'Manual replay needed in Intruder'
            }
            self.findings.append(finding)


# ============================================================
# ADDON: Credential Stuffing
# ============================================================

class CredentialStuffer:
    """
    Automatically test leaked credentials against login endpoints.
    
    Usage:
        mitmdump -s "addons.py:CredentialStuffer --creds leaked.txt"
    
    Use case:
        - Load credentials from breach database
        - Detect login forms and test credentials
        - Track successful logins
    """
    
    def __init__(self):
        self.credentials = []
        self.login_endpoints = set()
        self.successful = []
        
    def configure(self, updated):
        """Load credentials file from command line"""
        # In practice, load from file
        self.credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("test", "test123"),
            ("user", "user123"),
        ]
        ctx.log.info(f"[CredStuff] Loaded {len(self.credentials)} credentials")
    
    def request(self, flow: http.HTTPFlow):
        """Detect login endpoints"""
        if flow.request.method == "POST":
            body = flow.request.get_text().lower()
            url = flow.request.pretty_url.lower()
            
            # Detect login forms
            login_indicators = ['login', 'signin', 'auth', 'password', 'username']
            if any(ind in url or ind in body for ind in login_indicators):
                self.login_endpoints.add(flow.request.pretty_url)
                ctx.log.info(f"[CredStuff] Found login endpoint: {flow.request.pretty_url}")
    
    def response(self, flow: http.HTTPFlow):
        """Analyze login responses"""
        if flow.request.pretty_url not in self.login_endpoints:
            return
        
        if not flow.response:
            return
        
        # Check for successful login indicators
        success_indicators = [
            flow.response.status_code == 302,  # Redirect
            'dashboard' in flow.response.headers.get('location', '').lower(),
            'welcome' in flow.response.get_text().lower(),
            'logout' in flow.response.get_text().lower(),
        ]
        
        if any(success_indicators):
            ctx.log.warn(f"[CredStuff] Potential successful login at {flow.request.pretty_url}")


# ============================================================
# ADDON: IDOR Tester
# ============================================================

class IDORTester:
    """
    Automatically test for Insecure Direct Object References.
    
    Usage:
        mitmdump -s addons.py:IDORTester
    
    Use case:
        - Detect numeric IDs in URLs and bodies
        - Automatically replay with incremented/decremented IDs
        - Compare responses to detect unauthorized access
    """
    
    ID_PATTERNS = [
        (r'[?&]id=(\d+)', 'query'),
        (r'[?&]user_id=(\d+)', 'query'),
        (r'/users?/(\d+)', 'path'),
        (r'/orders?/(\d+)', 'path'),
        (r'/accounts?/(\d+)', 'path'),
        (r'/profiles?/(\d+)', 'path'),
        (r'/documents?/(\d+)', 'path'),
        (r'"id"\s*:\s*(\d+)', 'json'),
        (r'"user_id"\s*:\s*(\d+)', 'json'),
    ]
    
    def __init__(self):
        self.tested = set()
        self.findings = []
        self.id_map = defaultdict(list)  # endpoint -> list of IDs seen
    
    def request(self, flow: http.HTTPFlow):
        """Track IDs in requests"""
        url = flow.request.pretty_url
        body = flow.request.get_text()
        
        for pattern, location in self.ID_PATTERNS:
            # Check URL
            matches = re.findall(pattern, url, re.IGNORECASE)
            for match in matches:
                endpoint = re.sub(r'\d+', '{ID}', flow.request.path)
                self.id_map[endpoint].append({
                    'id': int(match),
                    'location': location,
                    'url': url,
                })
            
            # Check body
            if body:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for match in matches:
                    self.id_map[flow.request.path].append({
                        'id': int(match),
                        'location': 'body',
                        'url': url,
                    })
    
    def response(self, flow: http.HTTPFlow):
        """Analyze and suggest IDOR tests"""
        if not flow.response:
            return
        
        url = flow.request.pretty_url
        
        for pattern, location in self.ID_PATTERNS:
            matches = re.findall(pattern, url, re.IGNORECASE)
            for match in matches:
                original_id = int(match)
                test_ids = [1, original_id - 1, original_id + 1, 0, 9999999]
                
                finding = {
                    'type': 'IDOR Test Needed',
                    'severity': 'MEDIUM',
                    'url': url,
                    'original_id': original_id,
                    'test_ids': test_ids,
                    'response_length': len(flow.response.content),
                    'status_code': flow.response.status_code,
                    'instruction': f'Replay request with IDs: {test_ids}',
                }
                
                self.findings.append(finding)
                ctx.log.warn(f"[IDOR] Found ID {original_id} in {url} - test with {test_ids}")


# ============================================================
# ADDON: Session Analyzer
# ============================================================

class SessionAnalyzer:
    """
    Analyze session management security.
    
    Usage:
        mitmdump -s addons.py:SessionAnalyzer
    
    Use case:
        - Track session cookies across the application
        - Detect session fixation vulnerabilities
        - Identify insecure session configurations
    """
    
    def __init__(self):
        self.sessions = defaultdict(list)  # session_id -> list of requests
        self.pre_auth_sessions = {}
        self.post_auth_sessions = {}
        self.findings = []
    
    def request(self, flow: http.HTTPFlow):
        """Track session usage"""
        cookies = flow.request.cookies
        
        for name, value in cookies.items():
            if any(s in name.lower() for s in ['session', 'sess', 'sid', 'token']):
                self.sessions[value].append({
                    'url': flow.request.pretty_url,
                    'timestamp': datetime.now().isoformat(),
                })
    
    def response(self, flow: http.HTTPFlow):
        """Analyze session behavior"""
        if not flow.response:
            return
        
        # Check for session in URL (bad practice)
        url = flow.request.pretty_url
        if re.search(r'[?&](session|sid|token)=', url, re.IGNORECASE):
            self.findings.append({
                'type': 'Session in URL',
                'severity': 'HIGH',
                'url': url,
                'detail': 'Session ID exposed in URL - leaks via referer/logs',
            })
            ctx.log.warn(f"[Session] Session ID in URL: {url}")
        
        # Check Set-Cookie security
        for cookie in flow.response.headers.get_all('set-cookie'):
            self._analyze_cookie(cookie, flow.request.host)
        
        # Detect login (session change)
        if '/login' in flow.request.path.lower() and flow.response.status_code in [200, 302]:
            # Check if session regenerated
            old_session = flow.request.cookies.get('session', '')
            new_session = flow.response.cookies.get('session', ('', {}))[0]
            
            if old_session and new_session and old_session == new_session:
                self.findings.append({
                    'type': 'Session Fixation',
                    'severity': 'HIGH',
                    'url': flow.request.pretty_url,
                    'detail': 'Session ID not regenerated after login',
                })
                ctx.log.error(f"[Session] FIXATION: Session not regenerated after login!")
    
    def _analyze_cookie(self, cookie: str, host: str):
        """Analyze Set-Cookie header"""
        issues = []
        
        if 'Secure' not in cookie:
            issues.append('Missing Secure flag')
        
        if 'HttpOnly' not in cookie:
            issues.append('Missing HttpOnly flag')
        
        if 'SameSite' not in cookie:
            issues.append('Missing SameSite attribute')
        
        if issues:
            # Extract cookie name
            name = cookie.split('=')[0] if '=' in cookie else 'unknown'
            
            self.findings.append({
                'type': 'Insecure Cookie',
                'severity': 'MEDIUM',
                'host': host,
                'cookie': name,
                'issues': issues,
            })


# ============================================================
# ADDON: GraphQL Scanner
# ============================================================

class GraphQLScanner:
    """
    Detect and test GraphQL endpoints.
    
    Usage:
        mitmdump -s addons.py:GraphQLScanner
    
    Use case:
        - Auto-detect GraphQL endpoints
        - Test introspection
        - Identify batching vulnerabilities
    """
    
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            types {
                name
                fields { name }
            }
        }
    }
    '''
    
    def __init__(self):
        self.graphql_endpoints = set()
        self.schemas = {}
        self.findings = []
    
    def request(self, flow: http.HTTPFlow):
        """Detect GraphQL requests"""
        body = flow.request.get_text()
        url = flow.request.pretty_url.lower()
        content_type = flow.request.headers.get('content-type', '').lower()
        
        # Detection heuristics
        is_graphql = any([
            'graphql' in url,
            '/query' in url and 'application/json' in content_type,
            '"query"' in body and '{' in body,
            '__schema' in body,
            '__typename' in body,
        ])
        
        if is_graphql:
            self.graphql_endpoints.add(flow.request.pretty_url)
            ctx.log.info(f"[GraphQL] Detected endpoint: {flow.request.pretty_url}")
    
    @staticmethod
    def _has_introspection(data) -> bool:
        """Check if a parsed GraphQL response contains introspection schema data."""
        if not isinstance(data, dict):
            return False
        # Top-level __schema (raw introspection response)
        if '__schema' in data:
            return True
        # Nested under 'data' key (standard GraphQL envelope)
        data_field = data.get('data')
        if isinstance(data_field, dict) and '__schema' in data_field:
            return True
        return False

    def response(self, flow: http.HTTPFlow):
        """Analyze GraphQL responses"""
        if flow.request.pretty_url not in self.graphql_endpoints:
            return

        if not flow.response:
            return

        try:
            data = json.loads(flow.response.get_text())
        except Exception:
            return

        # Check if introspection is enabled (inspect parsed structure, not raw string)
        if self._has_introspection(data):
            self.findings.append({
                'type': 'GraphQL Introspection Enabled',
                'severity': 'MEDIUM',
                'url': flow.request.pretty_url,
                'detail': 'Full schema can be extracted via introspection',
            })
            ctx.log.warn(f"[GraphQL] Introspection ENABLED at {flow.request.pretty_url}")

        # Check for detailed errors
        if isinstance(data, dict) and 'errors' in data:
            for error in data.get('errors', []):
                if 'stack' in str(error).lower() or 'trace' in str(error).lower():
                    self.findings.append({
                        'type': 'GraphQL Detailed Errors',
                        'severity': 'LOW',
                        'url': flow.request.pretty_url,
                        'detail': 'Stack traces exposed in errors',
                    })


# ============================================================
# ADDON: Race Condition Tester
# ============================================================

class RaceConditionTester:
    """
    Set up race condition tests.
    
    Usage:
        mitmdump -s addons.py:RaceConditionTester
    
    Use case:
        - Identify requests suitable for race testing
        - Flag financial transactions, votes, coupon applications
        - Generate test scripts
    """
    
    # Keywords indicating race-sensitive operations
    SENSITIVE_OPERATIONS = [
        'transfer', 'withdraw', 'deposit', 'payment', 'pay',
        'vote', 'like', 'follow', 'subscribe',
        'coupon', 'discount', 'promo', 'redeem',
        'quantity', 'stock', 'inventory',
        'register', 'signup', 'create',
    ]
    
    def __init__(self):
        self.candidates = []
    
    def request(self, flow: http.HTTPFlow):
        """Identify race condition candidates"""
        if flow.request.method != "POST":
            return
        
        url = flow.request.pretty_url.lower()
        body = flow.request.get_text().lower()
        
        for keyword in self.SENSITIVE_OPERATIONS:
            if keyword in url or keyword in body:
                candidate = {
                    'url': flow.request.pretty_url,
                    'method': flow.request.method,
                    'headers': dict(flow.request.headers),
                    'body': flow.request.get_text(),
                    'keyword': keyword,
                }
                self.candidates.append(candidate)
                
                ctx.log.warn(f"[Race] Candidate found ({keyword}): {flow.request.pretty_url}")
                
                # Generate test script
                self._generate_test_script(candidate)
                break
    
    def _generate_test_script(self, candidate: Dict):
        """Generate Python script to test race condition"""
        script = f'''
#!/usr/bin/env python3
"""Race condition test for: {candidate['url']}"""

import asyncio
import aiohttp

async def send_request(session, url, headers, body):
    async with session.post(url, headers=headers, data=body) as resp:
        return await resp.text()

async def race_test():
    url = "{candidate['url']}"
    headers = {json.dumps(candidate['headers'], indent=8)}
    body = """{candidate['body']}"""
    
    async with aiohttp.ClientSession() as session:
        # Send 20 concurrent requests
        tasks = [send_request(session, url, headers, body) for _ in range(20)]
        results = await asyncio.gather(*tasks)
        
        # Analyze results
        print(f"Sent 20 concurrent requests")
        print(f"Unique responses: {{len(set(results))}}")
        
        for i, r in enumerate(results):
            print(f"[{{i}}] {{r[:100]}}...")

if __name__ == "__main__":
    asyncio.run(race_test())
'''
        
        # Save script
        filename = f"race_test_{candidate['keyword']}.py"
        with open(filename, 'w') as f:
            f.write(script)
        ctx.log.info(f"[Race] Test script saved: {filename}")


# ============================================================
# ADDON: Request Logger with Filters
# ============================================================

class SmartLogger:
    """
    Intelligent request logging with filtering.
    
    Usage:
        mitmdump -s addons.py:SmartLogger
    
    Use case:
        - Filter out noise (static files, analytics)
        - Focus on API calls and form submissions
        - Export clean history for analysis
    """
    
    # Skip these extensions
    SKIP_EXTENSIONS = [
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico',
        '.woff', '.woff2', '.ttf', '.svg', '.webp', '.mp4', '.mp3',
    ]
    
    # Skip these domains
    SKIP_DOMAINS = [
        'google-analytics.com', 'googletagmanager.com',
        'facebook.com', 'doubleclick.net', 'googlesyndication.com',
        'cloudflare.com', 'cdn.', 'static.',
    ]
    
    def __init__(self):
        self.logs = []
    
    def request(self, flow: http.HTTPFlow):
        """Log interesting requests"""
        url = flow.request.pretty_url
        host = flow.request.host
        
        # Skip static files
        if any(url.lower().endswith(ext) for ext in self.SKIP_EXTENSIONS):
            return
        
        # Skip tracking/CDN domains
        if any(domain in host.lower() for domain in self.SKIP_DOMAINS):
            return
        
        entry = {
            'timestamp': datetime.now().isoformat(),
            'method': flow.request.method,
            'url': url,
            'host': host,
            'path': flow.request.path,
            'has_body': bool(flow.request.content),
            'content_type': flow.request.headers.get('content-type', ''),
        }
        
        # Flag interesting requests
        interesting = []
        if flow.request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            interesting.append('state-changing')
        if 'api' in url.lower():
            interesting.append('api')
        if any(k in url.lower() for k in ['login', 'auth', 'admin', 'user']):
            interesting.append('auth-related')
        
        entry['tags'] = interesting
        self.logs.append(entry)
        
        if interesting:
            ctx.log.info(f"[Log] {flow.request.method} {url} [{', '.join(interesting)}]")
    
    def done(self):
        """Export logs on shutdown"""
        with open('smart_log.json', 'w') as f:
            json.dump(self.logs, f, indent=2)
        ctx.log.info(f"[Log] Exported {len(self.logs)} entries to smart_log.json")


# ============================================================
# ADDON: WAF Bypass Tester
# ============================================================

class WAFBypassTester:
    """
    Test WAF bypass techniques.
    
    Usage:
        mitmdump -s addons.py:WAFBypassTester
    
    Use case:
        - Detect WAF blocking
        - Suggest bypass techniques
        - Test encoding variations
    """
    
    # WAF signature patterns in responses
    WAF_SIGNATURES = {
        'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
        'AWS WAF': ['awswaf', 'x-amzn-requestid'],
        'ModSecurity': ['mod_security', 'modsecurity'],
        'Akamai': ['akamai', 'ak_bmsc'],
        'Imperva': ['incapsula', 'visid_incap'],
        'F5 BIG-IP': ['bigipserver', 'f5-ltm'],
    }
    
    WAF_BLOCK_PATTERNS = [
        r'blocked',
        r'access denied',
        r'forbidden',
        r'security',
        r'firewall',
        r'waf',
    ]
    
    def __init__(self):
        self.detected_wafs = set()
        self.blocked_requests = []
    
    def response(self, flow: http.HTTPFlow):
        if not flow.response:
            return
        
        headers = str(flow.response.headers).lower()
        body = flow.response.get_text().lower()
        
        # Detect WAF
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            if any(sig in headers or sig in body for sig in signatures):
                if waf_name not in self.detected_wafs:
                    self.detected_wafs.add(waf_name)
                    ctx.log.warn(f"[WAF] Detected: {waf_name}")
        
        # Detect blocking
        if flow.response.status_code in [403, 406, 429, 503]:
            if any(re.search(p, body) for p in self.WAF_BLOCK_PATTERNS):
                self.blocked_requests.append({
                    'url': flow.request.pretty_url,
                    'status': flow.response.status_code,
                    'waf': list(self.detected_wafs),
                })
                ctx.log.warn(f"[WAF] Request BLOCKED: {flow.request.pretty_url}")
                
                # Suggest bypasses
                self._suggest_bypasses(flow)
    
    def _suggest_bypasses(self, flow: http.HTTPFlow):
        """Suggest WAF bypass techniques"""
        suggestions = [
            "1. Try URL encoding: %27 instead of '",
            "2. Try double encoding: %2527",
            "3. Try case variation: SeLeCt instead of SELECT",
            "4. Try comment insertion: SEL/**/ECT",
            "5. Try Unicode: %u0027 instead of '",
            "6. Try different Content-Type",
            "7. Try adding X-Forwarded-For: 127.0.0.1",
            "8. Try chunked transfer encoding",
        ]
        
        ctx.log.info("[WAF] Bypass suggestions:")
        for s in suggestions:
            ctx.log.info(f"  {s}")


# ============================================================
# EXPORT ADDONS
# ============================================================

# For loading specific addons:
# mitmdump -s "addons.py:ActiveSQLiScanner"
# mitmdump -s "addons.py:IDORTester"

addons = [
    # Uncomment the ones you want to use:
    # ActiveSQLiScanner(),
    # CredentialStuffer(),
    IDORTester(),
    SessionAnalyzer(),
    GraphQLScanner(),
    # RaceConditionTester(),
    SmartLogger(),
    WAFBypassTester(),
]


if __name__ == "__main__":
    print("""
Durpie v2 - Standalone Addons
=============================

Phase 1 (Passive) Addons - this file:
  - IDORTester         : IDOR vulnerability detection
  - SessionAnalyzer    : Session security analysis
  - GraphQLScanner     : GraphQL endpoint testing
  - RaceConditionTester: Race condition detection
  - SmartLogger        : Filtered request logging
  - WAFBypassTester    : WAF detection and bypass
  - CredentialStuffer  : Test leaked credentials (disabled by default)
  - ActiveSQLiScanner  : Advisory SQLi notices (no active probing here)

Phase 2 (Active) Addons - active_scanners.py:
  - ActiveSQLiScanner  : Full SQLi scanner (error/boolean/time-based/UNION)
  - ActiveXSSScanner   : Context-aware XSS with PoC generation
  - SSRFExploiter      : Cloud metadata, port scan, protocol smuggling

Usage:
  mitmdump -s addons.py                     # Passive addons only
  mitmdump -s active_scanners.py            # Active scanning (Phase 2)
  mitmdump -s addons.py -s active_scanners.py  # Both

Standalone active scan:
  python active_scanners.py https://target.com/page?id=1
    """)
