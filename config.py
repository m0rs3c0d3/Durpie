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
    "active_scanning": False,
    
    # Rate limiting (requests per second, 0 = unlimited)
    "rate_limit": 0,
    
    # Skip testing static files
    "skip_static": True,
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
    print(f"""
Durpie Configuration
====================

Target: {TARGET['domain']}
Subdomains: {TARGET['include_subdomains']}
Additional: {TARGET['additional_domains']}

Scanners enabled:
{chr(10).join(f"  - {k}: {v}" for k, v in SCANNER['enabled'].items())}

Active scanning: {SCANNER['active_scanning']}
""")
