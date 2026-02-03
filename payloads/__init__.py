#!/usr/bin/env python3
"""
Durpie v2 - Payload Library
===========================

Comprehensive collection of security testing payloads.

Usage:
    from payloads import sqli, xss, ssrf, auth, traversal
    
    # Or import specific categories
    from payloads.sqli import AUTH_BYPASS, DETECTION
    from payloads.xss import EVENT_HANDLERS, FILTER_BYPASS
    from payloads.ssrf import LOCALHOST, AWS_METADATA
    from payloads.auth import DEFAULT_CREDENTIALS, COMMON_PASSWORDS
    from payloads.traversal import LINUX_FILES, PHP_WRAPPERS
"""

from . import sqli
from . import xss
from . import ssrf
from . import auth
from . import traversal

# Quick access to most common payloads
SQLI_QUICK = sqli.DETECTION + sqli.AUTH_BYPASS[:10]
XSS_QUICK = xss.DETECTION + xss.EVENT_HANDLERS[:10]
SSRF_QUICK = ssrf.LOCALHOST[:10] + ssrf.AWS_METADATA[:5]
AUTH_QUICK = auth.DEFAULT_CREDENTIALS[:20]
LFI_QUICK = traversal.FULL_UNIX_PAYLOADS[:20]

__all__ = [
    'sqli',
    'xss', 
    'ssrf',
    'auth',
    'traversal',
    'SQLI_QUICK',
    'XSS_QUICK',
    'SSRF_QUICK',
    'AUTH_QUICK',
    'LFI_QUICK',
]

if __name__ == "__main__":
    print("""
Durpie Payload Library
======================

Modules:
  - sqli      : SQL Injection payloads
  - xss       : Cross-Site Scripting payloads  
  - ssrf      : Server-Side Request Forgery payloads
  - auth      : Authentication attack payloads
  - traversal : Path traversal / LFI payloads

Quick access:
  - SQLI_QUICK  : Common SQLi payloads
  - XSS_QUICK   : Common XSS payloads
  - SSRF_QUICK  : Common SSRF payloads
  - AUTH_QUICK  : Common default credentials
  - LFI_QUICK   : Common LFI payloads

Example:
  from payloads import SQLI_QUICK
  
  for payload in SQLI_QUICK:
      test_injection(url, param, payload)
""")
