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

## Phase 5: Advanced Attacks ✅

> Implemented in `advanced_attacks.py` — load with `mitmdump -s advanced_attacks.py`

### ✅ Race Condition Framework
```
Priority: MEDIUM
Complexity: High
```
- [x] Automatic candidate detection (financial, votes, coupons — 35 keyword heuristics)
- [x] Parallel request generation (asyncio.gather burst, configurable concurrency)
- [x] Timing analysis (mean/stddev, outlier detection)
- [x] Turbo intruder-style single-packet attack (raw TCP last-byte sync via asyncio streams)
- [x] Result comparison and anomaly detection (unique bodies, status code spread, timing stddev)

### ✅ Business Logic Scanner
```
Priority: MEDIUM
Complexity: High
```
- [x] Price manipulation detection (negative, zero, fractional, overflow values)
- [x] Quantity manipulation (negative, zero, extreme values)
- [x] Workflow bypass (step ordering tracked per session — out-of-order detection)
- [x] Negative value testing (covered in price/quantity manipulation)
- [x] Currency confusion (multi-currency parameter detection, USD/EUR/GBP switching)
- [x] Coupon stacking (multiple coupon parameter detection)

### ✅ File Upload Testing
```
Priority: MEDIUM
Complexity: Medium
```
- [x] Extension bypass (.php, .php3–7, .phtml, .phar, .php.jpg, .php%00.jpg, null-byte)
- [x] Content-Type manipulation (image/jpeg for PHP uploads)
- [x] Magic byte injection (GIF89a + PHP polyglot)
- [x] SVG XSS (inline script in SVG payload)
- [x] XXE via file upload (SVG with external entity to /etc/passwd)
- [x] Path traversal in filename (../../../etc/passwd, Windows variants)
- [x] Polyglot files (GIF+PHP, ASP/JSP extension variants)

### ✅ Deserialization Scanner
```
Priority: MEDIUM
Complexity: High
```
- [x] Java serialization detection (binary magic 0xACED0005 + Base64 rO0AB pattern)
- [x] PHP object injection (O:N:"ClassName" regex pattern)
- [x] Python pickle detection (binary opcode \x80\x02 / \x80\x04 / \x80\x05)
- [x] .NET deserialization (BinaryFormatter AAEAAAD///// + ViewState pattern)
- [x] Gadget chain generation (ysoserial/phpggc/pickle/dnspy DNS probe templates)

---

## Phase 6: Infrastructure ✅

> Implemented in `infra_scanner.py` — load with `mitmdump -s infra_scanner.py`
> Standalone: `python infra_scanner.py subdomains|portscan|cms <target>`

### ✅ Subdomain Enumeration
```
Priority: MEDIUM
Complexity: Low
```
- [x] DNS brute force (async socket.getaddrinfo via thread pool, 100+ wordlist, configurable concurrency)
- [x] Certificate transparency logs (crt.sh JSON API, aiohttp + stdlib urllib fallback)
- [x] Integration with external tools (subfinder `-silent`, amass `enum -passive` — auto-detected if installed)
- [x] Automatic scope expansion (new subdomains queued for CMS detection in mitmproxy hook)

### ✅ Port Scanning
```
Priority: LOW
Complexity: Low
```
- [x] Async TCP connect scan (asyncio.open_connection, configurable concurrency + timeout)
- [x] Service fingerprinting (port-number lookup table, 40+ well-known ports)
- [x] Banner grabbing (reads first 512 bytes; parses SSH/FTP/SMTP/POP3/IMAP/Redis banners)
- [x] High-risk port flagging (Redis, Docker daemon, RDP, VNC, Elasticsearch, MongoDB, etc.)

### ✅ CMS Detection
```
Priority: LOW
Complexity: Low
```
- [x] WordPress detection (6 path probes, version from readme/feed, 15 common plugin checks)
- [x] Plugin enumeration (wp-content/plugins/ — 403 = installed, 200 = publicly listed)
- [x] Drupal/Joomla/Magento detection (path heuristics + version extraction)
- [x] Known CVE checking (version prefix matching — WP/Drupal/Joomla/Magento CVE table)
- [x] Passive technology disclosure (X-Powered-By, X-Generator, generator meta tag, Server header)

---

## Phase 7: Reporting & Integration ✅

> Implemented in `reporter.py` — standalone CLI (no mitmproxy required)
> `python reporter.py report|burp|nuclei|junit|notify|github|list|verify`

### ✅ Report Generation
```
Priority: MEDIUM
Complexity: Medium
```
- [x] HTML report — self-contained single file; dark theme, severity cards, filterable/searchable findings table, per-finding expandable detail with CVSS + remediation
- [x] PDF export — "Print to PDF" button embedded in HTML (zero extra dependencies; browser-native)
- [x] Severity scoring — full CVSS v3.1 base score formula from vector string (no external libs); representative vectors per severity label
- [x] Remediation recommendations — 14 finding-type categories mapped to fix text + OWASP/PortSwigger references, embedded in HTML and Burp/Nuclei exports
- [x] Evidence / request / proof — detail, evidence, payload, and PoC fields rendered in report

### ✅ External Integrations
```
Priority: LOW
Complexity: Medium
```
- [x] Burp Suite import/export — XML `<issues>` format; bidirectional (export Durpie findings → Burp; import Burp scan XML → Durpie)
- [ ] OWASP ZAP compatibility — not implemented (ZAP uses proprietary session format; Nuclei templates are a better bridge)
- [x] Nuclei template generation — per-finding YAML templates with id, severity, path, payload, regex matchers; saved to `durpie-nuclei-templates/`
- [x] Webhook notifications — Slack (attachments) + Discord (embeds) via stdlib urllib; severity filter; color-coded by severity
- [x] CI/CD pipeline integration — JUnit XML output; `--fail-on HIGH` exit code 1; compatible with Jenkins, GitHub Actions, GitLab CI
- [x] GitHub issue creation — REST API (Bearer token); per-finding issue with CVSS, detail, remediation, labels; batch with min-severity filter

### ✅ Collaboration Features
```
Priority: LOW
Complexity: High
```
- [ ] Project sharing (requires server/API — future Phase 8)
- [x] Finding deduplication — SHA-256 hash of (type, url-path, parameter); duplicates skipped on load across all Durpie JSON output files
- [x] Team notes — per-finding notes stored in `durpie_findings_state.json`; persisted across sessions; shown in HTML report
- [x] Finding verification workflow — statuses: `unverified` → `confirmed` / `false_positive` / `fixed`; `false_positive` and `fixed` excluded from active findings and report

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
