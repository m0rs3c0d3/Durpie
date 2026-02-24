# Durpie Development Roadmap

Security-focused roadmap organized by priority and complexity.

## Legend

- 🔴 **Critical** - Core functionality, do first
- 🟠 **High** - Important for real-world use
- 🟡 **Medium** - Nice to have
- 🟢 **Low** - Future enhancements
- ✅ **Done**
- 🚧 **In Progress**
- 📋 **Planned**

---

## Phase 1: Foundation (Current)

### Core Proxy ✅
- [x] mitmproxy integration
- [x] HTTPS interception
- [x] Request/response logging
- [x] Target scoping (config.py)

### Passive Scanners ✅
- [x] SQL error detection
- [x] XSS reflection detection
- [x] Sensitive data scanner (API keys, emails, tokens)
- [x] Security headers audit
- [x] Cookie security audit
- [x] JWT analyzer
- [x] IDOR pattern detection
- [x] SSRF vector detection

### Payload Library ✅
- [x] SQLi payloads with explanations
- [x] XSS payloads with context breakouts
- [x] SSRF payloads (localhost, cloud metadata)
- [x] Auth payloads (defaults, common passwords)
- [x] Path traversal payloads
- [x] Advanced auth module (auth2.py)

### Tools ✅
- [x] Intruder (automated fuzzing)
- [x] Decoder utility
- [x] Response fingerprinting

---

## Phase 2: Active Scanning ✅

> Implemented in `active_scanners.py` — load with `mitmdump -s active_scanners.py`
> Standalone: `python active_scanners.py https://target.com/page?id=1`

### ✅ Active SQLi Scanner
```
Priority: CRITICAL
Complexity: Medium
```
- [x] Parameter discovery (query, body, headers, cookies)
- [x] Automatic payload injection
- [x] Error-based detection (DB error pattern matching per MySQL/PostgreSQL/MSSQL/SQLite/Oracle)
- [x] Boolean-based blind detection (TRUE vs FALSE response diff)
- [x] Time-based blind detection (SLEEP/WAITFOR with baseline timing)
- [x] UNION column enumeration (incremental NULL columns until no error)
- [x] Database fingerprinting (error message signatures per DB engine)
- [x] Data extraction automation (version(), user(), @@version extraction)

### ✅ Active XSS Scanner
```
Priority: CRITICAL
Complexity: Medium
```
- [x] Reflection point detection (canary-based)
- [x] Context detection (HTML body / attribute / script / URL)
- [x] Payload selection based on context
- [x] Filter detection and bypass attempts (case variation, SVG, template literals, entities)
- [ ] DOM XSS detection (requires headless browser — future Phase 5)
- [x] Proof-of-concept generation (minimal HTML PoC page)

### ✅ SSRF Exploitation
```
Priority: HIGH
Complexity: Medium
```
- [x] Automatic URL parameter detection (30+ parameter name heuristics)
- [x] Internal port scanning (15 common ports via SSRF)
- [x] Cloud metadata extraction (AWS, GCP, Azure, Alibaba, DigitalOcean)
- [x] Protocol smuggling (gopher payload generator for Redis/SMTP; dict protocol)
- [x] Blind SSRF via external callback (configurable callback_host)

---

## Phase 3: Authentication & Session ✅

> Implemented in `auth_testing.py` — load with `mitmdump -s auth_testing.py`

### ✅ Session Analysis
```
Priority: HIGH
Complexity: Medium
```
- [x] Session token entropy analysis (Shannon entropy + charset heuristics)
- [x] Session fixation detection (pre/post-login session ID comparison)
- [ ] Session timeout testing (manual — requires waiting)
- [ ] Concurrent session testing (manual — requires two browsers)
- [x] Session invalidation on logout (detects missing Max-Age=0 on logout)
- [ ] Session invalidation on password change (future: track change flows)

### ✅ OAuth/OIDC Testing
```
Priority: HIGH
Complexity: High
```
- [x] Redirect URI validation testing (8 bypass payload variants)
- [x] State parameter validation (presence + entropy check)
- [x] PKCE implementation check (code_challenge presence)
- [x] Token leakage detection (URL query params, fragments, response body)
- [x] Scope escalation testing (dangerous scope detection)
- [ ] IdP confusion attacks (future: multi-IdP issuer validation)

### ✅ JWT Deep Analysis
```
Priority: HIGH
Complexity: Medium
```
- [x] Algorithm confusion attacks (RS256→HS256 using public key as HMAC secret)
- [x] Key brute forcing (35+ common secrets wordlist)
- [x] JWK injection (attacker-controlled key embedded in header)
- [x] Kid parameter attacks (SQL injection + path traversal variants)
- [x] Claim manipulation testing (role/admin/scope privilege escalation advisory)
- [x] Token expiration bypass (forged tokens + expired-but-accepted detection)

### ✅ MFA Testing
```
Priority: MEDIUM
Complexity: Medium
```
- [ ] Backup code brute force (advisory — entropy analysis implemented)
- [x] OTP bypass techniques (client-side bypass via response manipulation)
- [x] MFA fatigue simulation (push notification endpoint detection)
- [ ] Device trust manipulation (future)
- [x] Recovery flow testing (step-skip detection, rate limit detection)

---

## Phase 4: API Security ✅

> Implemented in `api_testing.py` — load with `mitmdump -s api_testing.py`
> Standalone: `python api_testing.py rest https://api.target.com/v1/users`

### ✅ REST API Scanner
```
Priority: HIGH
Complexity: Medium
```
- [x] Endpoint discovery (80+ path wordlist, sensitivity-aware severity)
- [x] HTTP method testing (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD/TRACE)
- [x] HTTP Parameter Pollution (HPP) — duplicate param response diff
- [x] Mass assignment (18 privilege fields injected, response comparison)
- [x] Rate limit testing (30-request burst, 429 detection)
- [x] Version testing (/v1/ vs /v2/ vs /api/v1/ — 8 prefixes)

### ✅ GraphQL Scanner
```
Priority: HIGH
Complexity: Medium
```
- [x] Introspection detection (probe + full schema extraction)
- [x] Schema extraction (all types, fields, mutations, directives)
- [x] Query depth DoS (incremental depth 5/10/15, error pattern detection)
- [x] Batch query attacks (array batching + alias batching)
- [x] Field suggestion brute force ("Did you mean?" error leakage)
- [x] Authorization bypass per field (31 sensitive field probes)

### ✅ WebSocket Testing
```
Priority: MEDIUM
Complexity: High
```
- [x] Message interception and injection payload generation
- [x] Cross-site WebSocket hijacking (CSWSH PoC HTML generation)
- [x] Origin validation testing (mismatch detection)
- [x] Message injection (XSS, SQLi, SSTI, path traversal, prototype pollution)
- [x] Sub-protocol confusion detection
- [x] Missing authentication on upgrade detection

---

## Phase 5: Advanced Attacks 🟡

### 📋 Race Condition Framework
```
Priority: MEDIUM
Complexity: High
```
- [ ] Automatic candidate detection (financial, votes, coupons)
- [ ] Parallel request generation
- [ ] Timing analysis
- [ ] Turbo intruder-style single-packet attack
- [ ] Result comparison and anomaly detection

### 📋 Business Logic Scanner
```
Priority: MEDIUM
Complexity: High
```
- [ ] Price manipulation detection
- [ ] Quantity manipulation
- [ ] Workflow bypass (skip steps)
- [ ] Negative value testing
- [ ] Currency confusion
- [ ] Coupon stacking

### 📋 File Upload Testing
```
Priority: MEDIUM
Complexity: Medium
```
- [ ] Extension bypass (.php.jpg, .php%00.jpg)
- [ ] Content-Type manipulation
- [ ] Magic byte injection
- [ ] SVG XSS
- [ ] XXE via file upload
- [ ] Path traversal in filename
- [ ] Polyglot files

### 📋 Deserialization Scanner
```
Priority: MEDIUM
Complexity: High
```
- [ ] Java serialization detection
- [ ] PHP object injection
- [ ] Python pickle detection
- [ ] .NET deserialization
- [ ] Gadget chain generation

---

## Phase 6: Infrastructure 🟡

### 📋 Subdomain Enumeration
```
Priority: MEDIUM
Complexity: Low
```
- [ ] DNS brute force
- [ ] Certificate transparency logs
- [ ] Integration with external tools (amass, subfinder)
- [ ] Automatic scope expansion

### 📋 Port Scanning
```
Priority: LOW
Complexity: Low
```
- [ ] Internal port scan via SSRF
- [ ] Service fingerprinting
- [ ] Banner grabbing

### 📋 CMS Detection
```
Priority: LOW
Complexity: Low
```
- [ ] WordPress detection and version
- [ ] Plugin enumeration
- [ ] Drupal/Joomla/Magento detection
- [ ] Known CVE checking

---

## Phase 7: Reporting & Integration 🟢

### 📋 Report Generation
```
Priority: MEDIUM
Complexity: Medium
```
- [ ] HTML report template
- [ ] PDF export
- [ ] Severity scoring (CVSS)
- [ ] Remediation recommendations
- [ ] Evidence screenshots
- [ ] Request/response proof

### 📋 External Integrations
```
Priority: LOW
Complexity: Medium
```
- [ ] Burp Suite import/export
- [ ] OWASP ZAP compatibility
- [ ] Nuclei template integration
- [ ] Webhook notifications (Slack, Discord)
- [ ] CI/CD pipeline integration
- [ ] JIRA/GitHub issue creation

### 📋 Collaboration Features
```
Priority: LOW
Complexity: High
```
- [ ] Project sharing
- [ ] Finding deduplication
- [ ] Team notes
- [ ] Finding verification workflow

---

## Phase 8: UI & UX 🟢

### 📋 Web Interface
```
Priority: LOW
Complexity: High
```
- [ ] React/Vue dashboard
- [ ] Real-time traffic view
- [ ] Finding browser
- [ ] Request editor (Repeater)
- [ ] Attack configuration GUI
- [ ] Scope management UI

### 📋 CLI Improvements
```
Priority: MEDIUM
Complexity: Low
```
- [ ] Interactive mode
- [ ] Progress bars
- [ ] Colored output
- [ ] Tab completion
- [ ] Configuration wizard

---

## Security Considerations

### For Users
- Always get written authorization
- Document your scope clearly
- Don't store credentials in config.py (use env vars)
- Review findings before reporting (false positives)
- Respect rate limits

### For Contributors
- No hardcoded malicious payloads that phone home
- All external connections must be opt-in
- Payload files should be educational, not weaponized
- Include ethical use warnings
- Test against intentionally vulnerable apps (DVWA, WebGoat, Juice Shop)

---

## Contributing

### Good First Issues
1. Add more SQLi payloads for specific databases
2. Improve error messages
3. Add documentation for a scanner
4. Create test cases against DVWA
5. Add new payload category

### Intermediate
1. Implement a new passive scanner
2. Add response pattern to fingerprinter
3. Create Intruder attack type
4. Build wordlist generator

### Advanced
1. Implement active scanner
2. Add headless browser for DOM XSS
3. Build race condition framework
4. Create report generator

---

## Testing Environments

Recommended practice targets:
- [DVWA](https://github.com/digininja/DVWA) - Damn Vulnerable Web Application
- [WebGoat](https://owasp.org/www-project-webgoat/) - OWASP WebGoat
- [Juice Shop](https://owasp.org/www-project-juice-shop/) - OWASP Juice Shop
- [HackTheBox](https://www.hackthebox.com/) - CTF platform
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free labs

---

## Version History

### v2.0.0 (Current)
- mitmproxy backend
- Modular scanner architecture
- Payload library with explanations
- Smart auth testing (auth2.py)
- Intruder fuzzing tool

### v1.0.0
- Pure Python proxy (deprecated)
- Basic interception
- Limited HTTPS support

---

## Milestones

| Version | Target | Focus |
|---------|--------|-------|
| v2.1 | Q2 2024 | Active SQLi + XSS scanners |
| v2.2 | Q3 2024 | API security (REST + GraphQL) |
| v2.3 | Q4 2024 | Session/Auth deep testing |
| v3.0 | 2025 | Web UI + Collaboration |
