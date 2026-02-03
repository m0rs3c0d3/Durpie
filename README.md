# Durpie v2 🔓

**A modular web security testing toolkit powered by mitmproxy.**

Educational tool for learning web application security testing. Inspired by Burp Suite.

## ⚠️ Legal Disclaimer

**Only use against systems you own or have explicit written permission to test.**

Unauthorized access to computer systems is illegal. This tool is for:
- Security professionals with authorization
- Bug bounty hunters within program scope
- Students learning in lab environments
- Developers testing their own applications

## Installation

```bash
git clone https://github.com/yourusername/durpie.git
cd durpie
pip install mitmproxy aiohttp
```

## Quick Start

```bash
# 1. Edit your target
nano config.py  # Set TARGET["domain"] = "yourtarget.com"

# 2. Start proxy
mitmdump -s durpie.py -p 8080

# 3. Configure browser proxy: 127.0.0.1:8080

# 4. Install CA cert: http://mitm.it

# 5. Browse your target - findings auto-saved
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       MITMPROXY                             │
│   HTTPS Interception · HTTP/2 · WebSockets · Certificates   │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   SCANNERS   │    │    TOOLS     │    │   PAYLOADS   │
├──────────────┤    ├──────────────┤    ├──────────────┤
│ SQLi         │    │ Intruder     │    │ sqli.py      │
│ XSS          │    │ Decoder      │    │ xss.py       │
│ SSRF         │    │ Repeater     │    │ ssrf.py      │
│ IDOR         │    │ Auth Tester  │    │ auth.py      │
│ JWT          │    │              │    │ auth2.py     │
│ Headers      │    │              │    │ traversal.py │
└──────────────┘    └──────────────┘    └──────────────┘
```

## File Structure

```
durpie/
├── config.py           # ← EDIT THIS: Set your target
├── run.py              # Quick start helper
├── durpie.py           # Main mitmproxy addon (all scanners)
├── addons.py           # Individual scanners for focused testing
├── intruder.py         # Automated fuzzing tool
├── README.md
├── ROADMAP.md          # Development roadmap
├── LICENSE
└── payloads/
    ├── __init__.py
    ├── sqli.py         # SQL injection (with explanations)
    ├── xss.py          # Cross-site scripting
    ├── ssrf.py         # Server-side request forgery
    ├── auth.py         # Basic auth payloads
    ├── auth2.py        # Advanced auth testing
    └── traversal.py    # Path traversal / LFI
```

## Usage

### Passive Scanning

Browse normally - Durpie analyzes traffic without modifying requests:

```bash
mitmdump -s durpie.py -p 8080
```

### Intruder (Fuzzing)

```bash
python intruder.py -r request.txt -p wordlist.txt -P username password
```

### Smart Auth Testing

```python
from payloads.auth2 import AuthAttacker

attacker = AuthAttacker(target_domain="target.com", company_name="Target Corp")
attacker.setup(known_names=[("John", "Smith")])

for cred in attacker.smart_attack():
    # Handles rate limiting, lockout avoidance, response analysis
    result = test_login(cred.username, cred.password)
    attacker.record_attempt(cred, result)
```

### Payload Library

```python
from payloads import sqli, xss, ssrf

sqli.DETECTION        # Basic SQLi tests
sqli.AUTH_BYPASS      # Login bypass
xss.EVENT_HANDLERS    # <img onerror=...>
ssrf.AWS_METADATA     # Cloud credential theft
```

## Contributing

See [ROADMAP.md](ROADMAP.md) for planned features.

## License

MIT License - See [LICENSE](LICENSE)
