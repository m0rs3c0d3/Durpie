#!/usr/bin/env python3
"""
Durpie v2 - Quick Start Runner
==============================

Simple script to start Durpie with your target configuration.

Usage:
    1. Edit config.py to set your target
    2. Run: python run.py
    
Or with command line:
    python run.py --target example.com --port 8080
"""

import argparse
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_banner():
    print("""
    ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗███████╗    ██╗   ██╗██████╗ 
    ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║██╔════╝    ██║   ██║╚════██╗
    ██║  ██║██║   ██║██████╔╝██████╔╝██║█████╗      ██║   ██║ █████╔╝
    ██║  ██║██║   ██║██╔══██╗██╔═══╝ ██║██╔══╝      ╚██╗ ██╔╝██╔═══╝ 
    ██████╔╝╚██████╔╝██║  ██║██║     ██║███████╗     ╚████╔╝ ███████╗
    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝      ╚═══╝  ╚══════╝
    
    Web Security Testing Toolkit powered by mitmproxy
    """)


def print_config():
    """Print current configuration"""
    try:
        from config import TARGET, SCANNER
        
        print("""
┌─────────────────────────────────────────────────────────────────┐
│ CURRENT CONFIGURATION                                           │
├─────────────────────────────────────────────────────────────────┤""")
        print(f"│ Target Domain:    {TARGET['domain']:<44}│")
        print(f"│ Include Subdoms:  {str(TARGET['include_subdomains']):<44}│")
        print("""├─────────────────────────────────────────────────────────────────┤
│ SCANNERS ENABLED                                                │""")
        for scanner, enabled in SCANNER['enabled'].items():
            status = "✓" if enabled else "✗"
            print(f"│   {status} {scanner:<58}│")
        print(f"""├─────────────────────────────────────────────────────────────────┤
│ Active Scanning:  {str(SCANNER['active_scanning']):<44}│
└─────────────────────────────────────────────────────────────────┘""")
    except ImportError:
        print("[!] config.py not found. Using defaults.")


def print_usage():
    """Print usage instructions"""
    print("""
QUICK START
===========

1. Edit config.py:
   - Set TARGET['domain'] to your target
   - Enable/disable scanners as needed
   - Add authentication tokens if required

2. Start mitmproxy with Durpie:
   
   mitmdump -s durpie.py -p 8080    # Terminal mode
   mitmweb -s durpie.py -p 8080     # Web interface

3. Configure browser proxy:
   - Proxy: 127.0.0.1:8080
   - Install CA: http://mitm.it

4. Browse target - findings saved to durpie_findings.json


PAYLOAD LIBRARY
===============

from payloads import sqli, xss, ssrf, auth, traversal

sqli.DETECTION       # SQL injection detection
sqli.AUTH_BYPASS     # Login bypass payloads
xss.EVENT_HANDLERS   # XSS via HTML events
ssrf.AWS_METADATA    # Cloud metadata URLs
auth.DEFAULT_CREDS   # Default logins
traversal.LINUX_FILES # Sensitive file paths
""")


def check_mitmproxy():
    """Check if mitmproxy is installed"""
    try:
        import mitmproxy
        return True
    except ImportError:
        return False


def main():
    parser = argparse.ArgumentParser(description="Durpie v2 - Security Testing Toolkit")
    parser.add_argument("-t", "--target", help="Target domain")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Proxy port")
    parser.add_argument("--config", action="store_true", help="Show config")
    parser.add_argument("--payloads", action="store_true", help="List payloads")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.config:
        print_config()
        return
    
    if args.payloads:
        print("\nPayload Modules:")
        print("=" * 40)
        try:
            from payloads import sqli, xss, ssrf, auth, traversal
            print(f"  sqli.py      - SQL injection")
            print(f"  xss.py       - Cross-site scripting")
            print(f"  ssrf.py      - Server-side request forgery")
            print(f"  auth.py      - Authentication attacks")
            print(f"  traversal.py - Path traversal / LFI")
        except ImportError as e:
            print(f"  Error: {e}")
        return
    
    if args.demo:
        os.system("python3 durpie.py --demo")
        return
    
    if not check_mitmproxy():
        print("""
[!] mitmproxy not installed!

    pip install mitmproxy aiohttp
""")
        return
    
    print_config()
    print_usage()
    
    print(f"\nStart with: mitmdump -s durpie.py -p {args.port}")


if __name__ == "__main__":
    main()
