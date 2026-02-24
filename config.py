#!/usr/bin/env python3
"""
Durpie v2 - Configuration
=========================

Edit this file to configure your target and attack settings.
"""

# ============================================================
# TARGET CONFIGURATION
# ============================================================

TARGET = {
    # Primary target domain (required)
    "domain": "example.com",
    
    # Include subdomains in scope
    "include_subdomains": True,
    
    # Additional domains in scope
    "additional_domains": [
        # "api.example.com",
        # "admin.example.com",
    ],
    
    # Domains to exclude (even if subdomain of target)
    "exclude_domains": [
        "cdn.example.com",
        "static.example.com",
    ],
    
    # Paths to exclude from scanning
    "exclude_paths": [
        "/logout",
        "/static/",
        "/assets/",
    ],
}

# ============================================================
# AUTHENTICATION
# ============================================================

AUTH = {
    # Session cookie to use for authenticated requests
    "session_cookie": {
        # "name": "session",
        # "value": "your-session-token-here",
    },
    
    # Bearer token for API requests
    "bearer_token": "",
    
    # Basic auth credentials
    "basic_auth": {
        # "username": "admin",
        # "password": "password123",
    },
    
    # Custom auth headers
    "custom_headers": {
        # "X-API-Key": "your-api-key",
        # "Authorization": "Custom xyz",
    },
}

# ============================================================
# SCANNER SETTINGS
# ============================================================

SCANNER = {
    # Enable/disable specific scanners
    "enabled": {
        "sqli": True,
        "xss": True,
        "sensitive_data": True,
        "security_headers": True,
        "cookies": True,
        "jwt": True,
        "idor": True,
        "ssrf": True,
    },

    # Active scanning (injects payloads - more intrusive)
    # Loads active_scanners.py Phase 2 modules when True
    "active_scanning": False,

    # Rate limiting for active scanning (seconds between requests, 0 = unlimited)
    # Recommended: 0.2 to avoid hammering the target
    "rate_limit": 0.2,

    # Skip testing static files
    "skip_static": True,
}


# ============================================================
# ACTIVE SCANNING SETTINGS (Phase 2)
# ============================================================

ACTIVE_SCAN = {
    # --- SQL Injection ---
    "sqli": {
        # Enable specific SQLi detection techniques
        "error_based": True,
        "boolean_based": True,
        "time_based": True,       # Slowest; causes intentional delays in responses
        "union_based": True,

        # Maximum parameters to test per endpoint (caps request count)
        "max_params": 20,

        # Seconds to SLEEP() for time-based detection
        # Must be long enough to distinguish from network jitter
        "time_delay": 5,
    },

    # --- XSS ---
    "xss": {
        # Test context-specific payloads (HTML / attribute / script / URL)
        "context_detection": True,

        # Try filter bypass payloads when basic payloads are blocked
        "filter_bypass": True,

        # Generate PoC HTML page for confirmed findings
        "generate_poc": True,
    },

    # --- SSRF ---
    "ssrf": {
        # Test localhost and internal IP bypass variants
        "test_localhost": True,

        # Test cloud provider metadata endpoints (AWS, GCP, Azure, Alibaba, DO)
        "test_cloud_metadata": True,

        # Port scan 127.0.0.1 via SSRF (only runs if SSRF is confirmed)
        "test_port_scan": True,

        # External callback host for blind SSRF detection.
        # Use Burp Collaborator, interact.sh, or your own server.
        # Leave empty to skip blind SSRF tests.
        # Example: "abc123.oastify.com"
        "callback_host": "",
    },

    # --- Output ---
    "output": {
        # Save active scan findings to a timestamped JSON file on shutdown
        "save_findings": True,

        # Directory for output files (created if it doesn't exist)
        "output_dir": "./durpie_output",
    },
}

# ============================================================
# INTRUDER SETTINGS
# ============================================================

INTRUDER = {
    # Concurrent requests
    "threads": 10,
    
    # Request timeout (seconds)
    "timeout": 30,
    
    # Follow redirects
    "follow_redirects": False,
    
    # Delay between requests (seconds)
    "delay": 0,
}

# ============================================================
# OUTPUT SETTINGS
# ============================================================

OUTPUT = {
    # Directory for output files
    "directory": "./durpie_output",
    
    # Export formats
    "export_json": True,
    "export_csv": True,
    
    # Verbosity level (0=quiet, 1=normal, 2=verbose)
    "verbosity": 1,
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_in_scope(host: str) -> bool:
    """Check if host is in target scope"""
    domain = TARGET["domain"].lower()
    host = host.lower()
    
    # Exact match
    if host == domain:
        return True
    
    # Subdomain match
    if TARGET["include_subdomains"] and host.endswith(f".{domain}"):
        # Check exclusions
        if host in [d.lower() for d in TARGET["exclude_domains"]]:
            return False
        return True
    
    # Additional domains
    if host in [d.lower() for d in TARGET["additional_domains"]]:
        return True
    
    return False


def is_path_excluded(path: str) -> bool:
    """Check if path should be excluded from scanning"""
    for excluded in TARGET["exclude_paths"]:
        if path.startswith(excluded):
            return True
    return False


def get_auth_headers() -> dict:
    """Get authentication headers for requests"""
    headers = {}
    
    if AUTH["bearer_token"]:
        headers["Authorization"] = f"Bearer {AUTH['bearer_token']}"
    
    if AUTH["basic_auth"].get("username"):
        import base64
        creds = f"{AUTH['basic_auth']['username']}:{AUTH['basic_auth']['password']}"
        encoded = base64.b64encode(creds.encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"
    
    headers.update(AUTH.get("custom_headers", {}))
    
    return headers


# ============================================================
# PRINT CONFIG ON IMPORT
# ============================================================

if __name__ == "__main__":
    active_techs = []
    if ACTIVE_SCAN["sqli"]["error_based"]:
        active_techs.append("SQLi(error)")
    if ACTIVE_SCAN["sqli"]["boolean_based"]:
        active_techs.append("SQLi(boolean)")
    if ACTIVE_SCAN["sqli"]["time_based"]:
        active_techs.append("SQLi(time)")
    if ACTIVE_SCAN["sqli"]["union_based"]:
        active_techs.append("SQLi(union)")
    if ACTIVE_SCAN["xss"]["context_detection"]:
        active_techs.append("XSS")
    if ACTIVE_SCAN["ssrf"]["test_localhost"]:
        active_techs.append("SSRF")

    print(f"""
Durpie Configuration
====================

Target: {TARGET['domain']}
Subdomains: {TARGET['include_subdomains']}
Additional: {TARGET['additional_domains']}

Passive Scanners enabled:
{chr(10).join(f"  - {k}: {v}" for k, v in SCANNER['enabled'].items())}

Active scanning: {SCANNER['active_scanning']}
Active techniques: {', '.join(active_techs) if active_techs else 'none'}
Rate limit: {SCANNER['rate_limit']}s between requests
SSRF callback: {ACTIVE_SCAN['ssrf']['callback_host'] or '(not configured)'}

To run active scanners:
  mitmdump -s active_scanners.py
  python active_scanners.py https://target.com/page?id=1
""")
