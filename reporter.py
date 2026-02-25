#!/usr/bin/env python3
"""
reporter.py — Phase 7 Reporting & Integration for Durpie
=========================================================
Aggregates findings from all Durpie scanners and produces:
  - Self-contained HTML report with severity filtering + CVSS scores
  - Burp Suite XML import/export
  - Nuclei YAML template generation
  - JUnit XML for CI/CD pipelines
  - Slack / Discord webhook notifications
  - GitHub issue creation

Usage:
    # Generate HTML report from all durpie_*.json files
    python reporter.py report [--out report.html] [--min-severity MEDIUM]

    # Export to Burp Suite XML
    python reporter.py burp [--out findings.xml]

    # Generate Nuclei templates
    python reporter.py nuclei [--out-dir ./nuclei-templates/]

    # JUnit XML (CI/CD)
    python reporter.py junit [--out results.xml] [--fail-on HIGH]

    # Notify webhooks
    python reporter.py notify --slack <url> --discord <url> [--min-severity HIGH]

    # Create GitHub issues
    python reporter.py github --token <token> --repo owner/repo [--min-severity HIGH]

    # List findings with verification status
    python reporter.py list [--status unverified]

    # Update verification status
    python reporter.py verify <hash> <confirmed|false_positive|fixed> [--notes "..."]

Authorized security testing only.
"""

import base64
import glob
import hashlib
import json
import math
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ============================================================
# Severity helpers
# ============================================================

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLOR = {
    "CRITICAL": "#d63031",
    "HIGH":     "#e17055",
    "MEDIUM":   "#fdcb6e",
    "LOW":      "#74b9ff",
    "INFO":     "#b2bec3",
}
SEVERITY_BADGE = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e74c3c",
    "MEDIUM":   "#f39c12",
    "LOW":      "#3498db",
    "INFO":     "#95a5a6",
}


def _sev_rank(s: str) -> int:
    try:
        return SEVERITY_ORDER.index(s.upper())
    except ValueError:
        return len(SEVERITY_ORDER)


# ============================================================
# CVSS v3.1 Calculator
# ============================================================

class CVSSv3Calculator:
    """Full CVSS v3.1 base score from vector string, or from severity label."""

    _AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    _AC  = {"L": 0.77, "H": 0.44}
    _UI  = {"N": 0.85, "R": 0.62}
    _C   = {"H": 0.56, "L": 0.22, "N": 0.00}
    _I   = {"H": 0.56, "L": 0.22, "N": 0.00}
    _A   = {"H": 0.56, "L": 0.22, "N": 0.00}
    _PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PR_C = {"N": 0.85, "L": 0.50, "H": 0.50}

    # Canonical representative vectors per severity label
    _VECTORS = {
        "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "HIGH":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "MEDIUM":   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "LOW":      "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
        "INFO":     "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
    }

    @classmethod
    def parse_vector(cls, vector: str) -> float:
        """Return CVSS 3.1 base score (0.0–10.0) from a vector string."""
        try:
            raw = re.sub(r'^CVSS:3\.[01]/', '', vector)
            parts: Dict[str, str] = {}
            for item in raw.split("/"):
                k, v = item.split(":")
                parts[k] = v
            scope = parts.get("S", "U")
            pr_map = cls._PR_C if scope == "C" else cls._PR_U
            av = cls._AV[parts["AV"]]
            ac = cls._AC[parts["AC"]]
            pr = pr_map[parts["PR"]]
            ui = cls._UI[parts["UI"]]
            c  = cls._C[parts["C"]]
            i  = cls._I[parts["I"]]
            a  = cls._A[parts["A"]]
            iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
            if scope == "U":
                impact = 6.42 * iss
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            exploit = 8.22 * av * ac * pr * ui
            if impact <= 0:
                return 0.0
            raw_score = (
                min(impact + exploit, 10.0) if scope == "U"
                else min(1.08 * (impact + exploit), 10.0)
            )
            return math.ceil(raw_score * 10) / 10  # CVSS roundup
        except Exception:
            return 0.0

    @classmethod
    def score(cls, severity: str) -> float:
        vec = cls._VECTORS.get(severity.upper())
        return cls.parse_vector(vec) if vec else 0.0

    @classmethod
    def vector(cls, severity: str) -> str:
        return cls._VECTORS.get(severity.upper(), cls._VECTORS["INFO"])


# ============================================================
# Remediation Advisor
# ============================================================

_REMEDIATIONS: Dict[str, Dict[str, Any]] = {
    "sql": {
        "title": "SQL Injection",
        "fix": (
            "Use parameterized queries / prepared statements exclusively. "
            "Never concatenate user input into SQL strings. "
            "Apply least-privilege DB accounts. "
            "Suppress DB error details in HTTP responses."
        ),
        "refs": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/sql-injection",
        ],
    },
    "xss": {
        "title": "Cross-Site Scripting",
        "fix": (
            "HTML-encode all user-controlled output. "
            "Implement Content-Security-Policy with nonce or strict-dynamic. "
            "Avoid innerHTML / eval() with untrusted data. "
            "Set HttpOnly + Secure on session cookies."
        ),
        "refs": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/cross-site-scripting",
        ],
    },
    "ssrf": {
        "title": "Server-Side Request Forgery",
        "fix": (
            "Whitelist allowed URL schemes and destination hosts. "
            "Block RFC-1918, loopback, and link-local (169.254.x.x) addresses. "
            "Route outbound requests through an allowlist-enforcing egress proxy. "
            "Disable HTTP redirects in server-side HTTP clients."
        ),
        "refs": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "jwt": {
        "title": "JWT Security",
        "fix": (
            "Explicitly whitelist the expected algorithm server-side; reject alg:none. "
            "Validate iss, aud, exp, and nbf claims. "
            "Rotate signing keys regularly; never expose the private key. "
            "Prefer asymmetric algorithms (RS256/ES256) over HS256 for public clients."
        ),
        "refs": [
            "https://portswigger.net/web-security/jwt",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
    },
    "idor": {
        "title": "Insecure Direct Object Reference",
        "fix": (
            "Perform server-side authorization on every object access. "
            "Use opaque identifiers (UUIDs) instead of sequential integers. "
            "Log and alert on access anomalies."
        ),
        "refs": [
            "https://portswigger.net/web-security/access-control/idor",
        ],
    },
    "deserialization": {
        "title": "Insecure Deserialization",
        "fix": (
            "Avoid native object deserialization of untrusted input. "
            "Prefer data-only formats (JSON with schema validation). "
            "If unavoidable, use an allowlist of permitted classes. "
            "Apply HMAC integrity checks to serialized blobs."
        ),
        "refs": [
            "https://portswigger.net/web-security/deserialization",
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
    },
    "upload": {
        "title": "Unrestricted File Upload",
        "fix": (
            "Validate file type by magic bytes, not extension or Content-Type. "
            "Store uploads outside the web root or in a separate origin. "
            "Never use client-provided filenames. "
            "Prevent execution of uploaded files."
        ),
        "refs": [
            "https://portswigger.net/web-security/file-upload",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        ],
    },
    "race": {
        "title": "Race Condition",
        "fix": (
            "Use database transactions with appropriate isolation levels. "
            "Implement server-side idempotency keys for financial operations. "
            "Apply pessimistic or optimistic locking for critical operations. "
            "Rate-limit sensitive endpoints."
        ),
        "refs": ["https://portswigger.net/web-security/race-conditions"],
    },
    "header": {
        "title": "Missing Security Header",
        "fix": (
            "Add the missing header to all responses. "
            "For HSTS: max-age=31536000; includeSubDomains; preload. "
            "For CSP: use report-only mode first, then enforce."
        ),
        "refs": [
            "https://securityheaders.com/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        ],
    },
    "cookie": {
        "title": "Insecure Cookie",
        "fix": "Set Secure, HttpOnly, SameSite=Lax/Strict flags. Review Domain and Path scope.",
        "refs": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    },
    "cms": {
        "title": "Outdated CMS / Known CVEs",
        "fix": (
            "Update the CMS and all plugins to the latest stable release. "
            "Subscribe to vendor security advisories. "
            "Remove unused plugins and themes. "
            "Restrict admin panel access by IP where possible."
        ),
        "refs": ["https://owasp.org/www-project-top-ten/"],
    },
    "graphql": {
        "title": "GraphQL Security",
        "fix": (
            "Disable introspection in production. "
            "Enforce query depth and complexity limits. "
            "Apply per-field authorization. "
            "Rate-limit or disable batch operations."
        ),
        "refs": [
            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        ],
    },
    "open port": {
        "title": "Exposed Network Service",
        "fix": (
            "Restrict access to this port with firewall rules. "
            "If the service must be public, ensure authentication, TLS, and patching. "
            "Disable the service if not required."
        ),
        "refs": [],
    },
    "default": {
        "title": "Security Finding",
        "fix": (
            "Review the finding details and apply defence-in-depth. "
            "Validate and sanitize all user input. "
            "Apply the principle of least privilege."
        ),
        "refs": ["https://owasp.org/www-project-top-ten/"],
    },
}


def get_remediation(finding_type: str) -> Dict[str, Any]:
    ft = finding_type.lower()
    for key in _REMEDIATIONS:
        if key != "default" and key in ft:
            return _REMEDIATIONS[key]
    return _REMEDIATIONS["default"]


# ============================================================
# Finding Store — load, deduplicate, verify
# ============================================================

class FindingStore:
    """
    Loads findings from all Durpie JSON output files, deduplicates by
    (type, url-path, parameter), and tracks verification status.
    """

    STATUSES = ("unverified", "confirmed", "false_positive", "fixed")

    def __init__(self, state_file: str = "durpie_findings_state.json"):
        self.findings: List[dict] = []
        self.state_file = state_file
        self._hashes: Set[str] = set()
        self._state: Dict[str, dict] = {}

    def _hash(self, f: dict) -> str:
        path = re.sub(r'[?#].*', '', f.get("url", ""))  # strip query + fragment
        key = "|".join([
            f.get("type", "").lower(),
            path,
            f.get("parameter", ""),
        ])
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def load_json_files(self, paths: List[str]) -> Tuple[int, int]:
        """Load findings; return (total_loaded, duplicates_skipped)."""
        loaded = dupes = 0
        for path in paths:
            try:
                with open(path) as fh:
                    data = json.load(fh)
                for r in data.get("findings", []):
                    h = self._hash(r)
                    if h in self._hashes:
                        dupes += 1
                        continue
                    self._hashes.add(h)
                    r["_hash"] = h
                    r["_source"] = os.path.basename(path)
                    r["_scanner"] = data.get("scanner", "unknown")
                    # Backfill CVSS
                    sev = r.get("severity", "INFO").upper()
                    r["_cvss"] = CVSSv3Calculator.score(sev)
                    r["_cvss_vector"] = CVSSv3Calculator.vector(sev)
                    r["_remediation"] = get_remediation(r.get("type", ""))
                    self.findings.append(r)
                    loaded += 1
            except Exception as exc:
                print(f"[warn] Could not load {path}: {exc}", file=sys.stderr)
        return loaded, dupes

    def load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file) as fh:
                    self._state = json.load(fh).get("state", {})
            except Exception:
                pass

    def save_state(self):
        out = {
            "state": self._state,
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        with open(self.state_file, "w") as fh:
            json.dump(out, fh, indent=2)

    def set_status(self, finding_hash: str, status: str, notes: str = ""):
        if status not in self.STATUSES:
            raise ValueError(f"status must be one of {self.STATUSES}")
        self._state[finding_hash] = {
            "status": status,
            "notes": notes,
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        self.save_state()

    def get_status(self, h: str) -> str:
        return self._state.get(h, {}).get("status", "unverified")

    def get_notes(self, h: str) -> str:
        return self._state.get(h, {}).get("notes", "")

    def active(self) -> List[dict]:
        return [
            f for f in self.findings
            if self.get_status(f.get("_hash", "")) not in ("false_positive", "fixed")
        ]

    def by_severity(self, findings: List[dict] = None) -> Dict[str, List[dict]]:
        src = findings if findings is not None else self.findings
        result: Dict[str, List[dict]] = defaultdict(list)
        for f in src:
            result[f.get("severity", "INFO").upper()].append(f)
        return dict(result)

    def stats(self, findings: List[dict] = None) -> Dict[str, int]:
        src = findings if findings is not None else self.active()
        counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in src:
            s = f.get("severity", "INFO").upper()
            counts[s] = counts.get(s, 0) + 1
        counts["total"] = len(src)
        return counts


# ============================================================
# HTML Report
# ============================================================

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Durpie Security Report — {title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0f1117;color:#e0e0e0;line-height:1.5}}
a{{color:#74b9ff}}
header{{background:linear-gradient(135deg,#1e2130,#2d3250);padding:28px 36px;border-bottom:2px solid #3d4466}}
header h1{{font-size:1.6rem;font-weight:700;color:#fff}}
header p{{color:#8892b0;font-size:.9rem;margin-top:4px}}
.container{{max-width:1200px;margin:0 auto;padding:24px 20px}}
.summary{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}}
.card{{background:#1a1d2e;border-radius:8px;padding:16px 22px;flex:1;min-width:120px;text-align:center;border:1px solid #2a2d42}}
.card .num{{font-size:2rem;font-weight:700}}
.card .lbl{{font-size:.75rem;color:#8892b0;text-transform:uppercase;letter-spacing:.05em}}
.controls{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;align-items:center}}
.controls input{{background:#1a1d2e;border:1px solid #3d4466;color:#e0e0e0;padding:7px 12px;border-radius:6px;flex:1;min-width:200px}}
.controls select{{background:#1a1d2e;border:1px solid #3d4466;color:#e0e0e0;padding:7px 10px;border-radius:6px}}
table{{width:100%;border-collapse:collapse;font-size:.875rem}}
thead th{{background:#1a1d2e;padding:10px 12px;text-align:left;border-bottom:2px solid #3d4466;color:#8892b0;font-weight:600;text-transform:uppercase;font-size:.75rem;letter-spacing:.05em}}
tbody tr{{border-bottom:1px solid #1e2130;cursor:pointer;transition:background .15s}}
tbody tr:hover{{background:#1e2130}}
td{{padding:10px 12px;vertical-align:top}}
.badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.7rem;font-weight:700;text-transform:uppercase;color:#fff}}
.detail-row{{display:none;background:#141624!important}}
.detail-row td{{padding:0}}
.detail-inner{{padding:16px 20px;border-left:3px solid #3d4466}}
.detail-inner h4{{color:#74b9ff;margin-bottom:8px;font-size:.9rem}}
.detail-inner pre{{background:#0f1117;padding:10px;border-radius:4px;overflow-x:auto;font-size:.8rem;white-space:pre-wrap;word-break:break-all;margin-bottom:10px}}
.detail-inner .fix{{background:#1a2a1a;border-left:3px solid #00b894;padding:10px 14px;border-radius:0 4px 4px 0;margin-bottom:10px;font-size:.85rem}}
.detail-inner .refs a{{display:block;font-size:.8rem;margin-bottom:2px}}
.detail-inner .cvss{{font-size:.8rem;color:#8892b0;margin-bottom:10px}}
.status-badge{{font-size:.7rem;padding:2px 7px;border-radius:4px;background:#2a2d42;color:#b2bec3}}
.status-confirmed{{background:#1a3a2a;color:#00b894}}
.status-false_positive{{background:#2a1a1a;color:#d63031}}
.status-fixed{{background:#1a2a3a;color:#74b9ff}}
.hidden{{display:none!important}}
footer{{text-align:center;padding:20px;color:#4a4d6a;font-size:.8rem;border-top:1px solid #1e2130;margin-top:32px}}
</style>
</head>
<body>
<header>
  <h1>🔍 Durpie Security Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; Target scope: {scope} &nbsp;|&nbsp; Total findings: {total}</p>
</header>
<div class="container">
  <div class="summary">
    <div class="card"><div class="num" style="color:{c_crit}">{n_crit}</div><div class="lbl">Critical</div></div>
    <div class="card"><div class="num" style="color:{c_high}">{n_high}</div><div class="lbl">High</div></div>
    <div class="card"><div class="num" style="color:{c_med}">{n_med}</div><div class="lbl">Medium</div></div>
    <div class="card"><div class="num" style="color:{c_low}">{n_low}</div><div class="lbl">Low</div></div>
    <div class="card"><div class="num" style="color:{c_info}">{n_info}</div><div class="lbl">Info</div></div>
  </div>
  <div class="controls">
    <input type="text" id="search" placeholder="Search findings…" oninput="filterTable()">
    <select id="sev-filter" onchange="filterTable()">
      <option value="">All severities</option>
      <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option>
    </select>
    <select id="status-filter" onchange="filterTable()">
      <option value="">All statuses</option>
      <option>unverified</option><option>confirmed</option><option>false_positive</option><option>fixed</option>
    </select>
  </div>
  <table id="findings-table">
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>CVSS</th><th>Type</th><th>URL</th><th>Parameter</th><th>Status</th>
      </tr>
    </thead>
    <tbody>
{rows}
    </tbody>
  </table>
</div>
<footer>Durpie &mdash; Authorized security testing only &mdash; {generated}</footer>
<script>
function filterTable(){{
  var s=document.getElementById('search').value.toLowerCase();
  var sev=document.getElementById('sev-filter').value.toUpperCase();
  var st=document.getElementById('status-filter').value;
  document.querySelectorAll('tr.finding-row').forEach(function(tr){{
    var text=tr.textContent.toLowerCase();
    var trSev=tr.dataset.sev||'';
    var trSt=tr.dataset.status||'';
    var show=(!s||text.includes(s))&&(!sev||trSev===sev)&&(!st||trSt===st);
    tr.classList.toggle('hidden',!show);
    var det=document.getElementById('det-'+tr.dataset.idx);
    if(det&&!show) det.classList.add('hidden');
  }});
}}
function toggleDetail(idx){{
  var row=document.getElementById('det-'+idx);
  if(!row) return;
  var vis=row.style.display==='table-row';
  document.querySelectorAll('.detail-row').forEach(function(r){{r.style.display='none';}});
  if(!vis) row.style.display='table-row';
}}
</script>
</body>
</html>
"""


def _esc(s: str) -> str:
    """HTML-escape a string."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _badge(severity: str) -> str:
    color = SEVERITY_BADGE.get(severity.upper(), "#95a5a6")
    return f'<span class="badge" style="background:{color}">{_esc(severity)}</span>'


def _status_badge(status: str) -> str:
    cls = f"status-{status}" if status != "unverified" else ""
    return f'<span class="status-badge {cls}">{_esc(status)}</span>'


class HTMLReporter:

    def generate(
        self,
        store: "FindingStore",
        output_path: str,
        title: str = "Security Assessment",
        min_severity: str = "INFO",
    ) -> str:
        findings = [
            f for f in store.active()
            if _sev_rank(f.get("severity", "INFO")) <= _sev_rank(min_severity)
        ]
        findings.sort(key=lambda f: (_sev_rank(f.get("severity", "INFO")), f.get("url", "")))

        stats = store.stats(findings)
        scope = ", ".join(sorted({
            re.sub(r'https?://', '', re.sub(r'/.*', '', f.get("url", "?")))
            for f in findings
        })[:8]) or "N/A"

        rows_html = []
        for idx, f in enumerate(findings):
            sev = f.get("severity", "INFO").upper()
            h = f.get("_hash", "")
            status = store.get_status(h)
            notes = store.get_notes(h)
            cvss = f.get("_cvss", 0.0)
            rem = f.get("_remediation", get_remediation(f.get("type", "")))
            detail_lines = _esc(f.get("detail", ""))
            evidence = _esc(f.get("evidence", ""))
            poc = _esc(f.get("poc", ""))
            refs_html = "".join(
                f'<a href="{_esc(r)}" target="_blank">{_esc(r)}</a>'
                for r in rem.get("refs", [])
            )
            rows_html.append(f"""\
      <tr class="finding-row" data-idx="{idx}" data-sev="{_esc(sev)}" data-status="{_esc(status)}" onclick="toggleDetail({idx})">
        <td>{idx+1}</td>
        <td>{_badge(sev)}</td>
        <td>{cvss:.1f}</td>
        <td>{_esc(f.get('type',''))}</td>
        <td style="word-break:break-all;max-width:300px">{_esc(f.get('url',''))}</td>
        <td>{_esc(f.get('parameter',''))}</td>
        <td>{_status_badge(status)}</td>
      </tr>
      <tr class="detail-row hidden" id="det-{idx}" data-idx="{idx}">
        <td colspan="7">
          <div class="detail-inner">
            <h4>Detail</h4>
            <pre>{detail_lines}</pre>
            {"<h4>Evidence</h4><pre>" + evidence + "</pre>" if evidence else ""}
            {"<h4>Proof of Concept</h4><pre>" + poc + "</pre>" if poc else ""}
            {"<h4>Notes</h4><pre>" + _esc(notes) + "</pre>" if notes else ""}
            <div class="cvss">CVSS v3.1 vector: {_esc(f.get('_cvss_vector','N/A'))} &nbsp;|&nbsp; Score: {cvss:.1f} &nbsp;|&nbsp; Source: {_esc(f.get('_source','?'))}</div>
            <h4>Remediation</h4>
            <div class="fix">{_esc(rem.get('fix',''))}</div>
            {"<div class='refs'>" + refs_html + "</div>" if refs_html else ""}
            <p style="font-size:.75rem;color:#4a4d6a;margin-top:8px">Hash: {_esc(h)}</p>
          </div>
        </td>
      </tr>""")

        html = _HTML_TEMPLATE.format(
            title=_esc(title),
            generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            scope=_esc(scope),
            total=stats["total"],
            n_crit=stats.get("CRITICAL", 0),
            n_high=stats.get("HIGH", 0),
            n_med=stats.get("MEDIUM", 0),
            n_low=stats.get("LOW", 0),
            n_info=stats.get("INFO", 0),
            c_crit=SEVERITY_COLOR["CRITICAL"],
            c_high=SEVERITY_COLOR["HIGH"],
            c_med=SEVERITY_COLOR["MEDIUM"],
            c_low=SEVERITY_COLOR["LOW"],
            c_info=SEVERITY_COLOR["INFO"],
            rows="\n".join(rows_html),
        )
        Path(output_path).write_text(html, encoding="utf-8")
        return output_path


# ============================================================
# Burp Suite XML export / import
# ============================================================

class BurpExporter:
    """Export findings as Burp Suite XML; import Burp scan results."""

    _SEV_MAP = {"CRITICAL": "High", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Information"}
    _SEV_BACK = {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Information": "INFO"}

    def export(self, findings: List[dict], output_path: str) -> str:
        root = ET.Element("issues")
        root.set("burpVersion", "Durpie-export")
        root.set("exportTime", datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y"))
        for idx, f in enumerate(findings):
            issue = ET.SubElement(root, "issue")
            ET.SubElement(issue, "serialNumber").text = str(idx + 1)
            ET.SubElement(issue, "type").text = "0"
            ET.SubElement(issue, "name").text = f.get("type", "Unknown")
            parsed = urlparse_safe(f.get("url", "http://unknown/"))
            host_el = ET.SubElement(issue, "host")
            host_el.set("ip", "")
            host_el.text = f"{parsed['scheme']}://{parsed['host']}"
            ET.SubElement(issue, "path").text = parsed["path"] or "/"
            ET.SubElement(issue, "location").text = f.get("parameter", "/")
            ET.SubElement(issue, "severity").text = self._SEV_MAP.get(
                f.get("severity", "INFO").upper(), "Information"
            )
            ET.SubElement(issue, "confidence").text = "Tentative"
            ET.SubElement(issue, "issueDetail").text = (
                f.get("detail", "") + "\n\nEvidence: " + f.get("evidence", "")
            )
            rem = get_remediation(f.get("type", ""))
            ET.SubElement(issue, "remediationDetail").text = rem.get("fix", "")
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(output_path, encoding="unicode", xml_declaration=True)
        return output_path

    def import_burp(self, xml_path: str) -> List[dict]:
        """Parse a Burp Scanner XML export into Durpie finding dicts."""
        findings = []
        try:
            tree = ET.parse(xml_path)
            for issue in tree.getroot().findall("issue"):
                host = (issue.findtext("host") or "").strip()
                path = (issue.findtext("path") or "/").strip()
                sev_str = (issue.findtext("severity") or "Information").strip()
                findings.append({
                    "type": issue.findtext("name") or "Unknown",
                    "severity": self._SEV_BACK.get(sev_str, "INFO"),
                    "url": host + path,
                    "detail": issue.findtext("issueDetail") or "",
                    "evidence": "",
                    "parameter": issue.findtext("location") or "",
                })
        except Exception as exc:
            print(f"[warn] Burp import error: {exc}", file=sys.stderr)
        return findings


def urlparse_safe(url: str) -> dict:
    try:
        p = urllib.parse.urlparse(url)
        return {"scheme": p.scheme or "https", "host": p.netloc or "unknown", "path": p.path}
    except Exception:
        return {"scheme": "https", "host": "unknown", "path": "/"}


# ============================================================
# Nuclei YAML template generator
# ============================================================

class NucleiExporter:
    """Generate Nuclei YAML templates from confirmed/high-severity findings."""

    _SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}

    def generate_templates(self, findings: List[dict], output_dir: str) -> List[str]:
        os.makedirs(output_dir, exist_ok=True)
        paths = []
        seen_ids: Set[str] = set()
        for f in findings:
            slug = re.sub(r'[^a-z0-9]+', '-', f.get("type", "finding").lower()).strip('-')
            base_id = f"durpie-{slug}"
            uid = base_id
            n = 2
            while uid in seen_ids:
                uid = f"{base_id}-{n}"
                n += 1
            seen_ids.add(uid)
            sev = self._SEV_MAP.get(f.get("severity", "INFO").upper(), "info")
            parsed = urlparse_safe(f.get("url", "http://unknown/"))
            param = f.get("parameter", "")
            payload = f.get("payload", "")
            evidence = f.get("evidence", "")
            # Build a path probe template
            yaml_lines = [
                f"id: {uid}",
                "",
                "info:",
                f"  name: {f.get('type', 'Finding')}",
                "  author: durpie",
                f"  severity: {sev}",
                f"  description: |",
                f"    {f.get('detail', '').splitlines()[0][:200] if f.get('detail') else 'Finding from Durpie scanner.'}",
                "  tags: durpie,automated",
                "",
                "requests:",
                "  - method: GET",
                "    path:",
                f"      - \"{{{{BaseURL}}}}{parsed['path']}\"",
            ]
            if param and payload:
                yaml_lines += [
                    "    payloads:",
                    f"      {param}:",
                    f"        - \"{payload.replace(chr(34), chr(39))}\"",
                ]
            if evidence:
                safe_evidence = re.escape(evidence[:60])
                yaml_lines += [
                    "    matchers:",
                    "      - type: regex",
                    f"        regex:",
                    f"          - \"{safe_evidence}\"",
                ]
            else:
                yaml_lines += [
                    "    matchers:",
                    "      - type: status",
                    "        status:",
                    "          - 200",
                ]
            out_path = os.path.join(output_dir, f"{uid}.yaml")
            Path(out_path).write_text("\n".join(yaml_lines) + "\n", encoding="utf-8")
            paths.append(out_path)
        return paths


# ============================================================
# JUnit XML (CI/CD)
# ============================================================

class JUnitExporter:
    """
    Generate JUnit XML suitable for CI/CD pipelines (Jenkins, GitHub Actions, etc.).
    Findings at or above fail_severity become <failure> elements.
    """

    def export(
        self,
        findings: List[dict],
        output_path: str,
        fail_severity: str = "HIGH",
    ) -> Tuple[str, int]:
        """Return (output_path, exit_code). exit_code=1 if any failures."""
        fail_rank = _sev_rank(fail_severity)
        suite = ET.Element("testsuite")
        suite.set("name", "Durpie Security Scan")
        suite.set("tests", str(len(findings)))
        suite.set("timestamp", datetime.now(timezone.utc).isoformat())
        failures = 0
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            tc = ET.SubElement(suite, "testcase")
            tc.set("name", f.get("type", "Unknown"))
            tc.set("classname", f"durpie.{sev.lower()}")
            tc.set("time", "0")
            if _sev_rank(sev) <= fail_rank:
                fail = ET.SubElement(tc, "failure")
                fail.set("message", f"[{sev}] {f.get('type','?')} @ {f.get('url','?')}")
                fail.text = (
                    f"URL: {f.get('url','')}\n"
                    f"Parameter: {f.get('parameter','')}\n"
                    f"Detail: {f.get('detail','')[:500]}\n"
                    f"CVSS: {f.get('_cvss', 0.0):.1f}"
                )
                failures += 1
        suite.set("failures", str(failures))
        tree = ET.ElementTree(suite)
        ET.indent(tree, space="  ")
        tree.write(output_path, encoding="unicode", xml_declaration=True)
        return output_path, (1 if failures > 0 else 0)


# ============================================================
# Webhook Notifier (Slack + Discord)
# ============================================================

class WebhookNotifier:
    """Send findings to Slack and/or Discord webhooks using stdlib only."""

    def __init__(self, slack_url: str = None, discord_url: str = None):
        self.slack_url = slack_url
        self.discord_url = discord_url

    def _post(self, url: str, payload: dict) -> bool:
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                url, data=data, headers={"Content-Type": "application/json"}, method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 204)
        except Exception as exc:
            print(f"[warn] Webhook error: {exc}", file=sys.stderr)
            return False

    def _slack_payload(self, f: dict) -> dict:
        sev = f.get("severity", "INFO").upper()
        color = SEVERITY_BADGE.get(sev, "#95a5a6")
        return {
            "attachments": [{
                "color": color,
                "title": f"[{sev}] {f.get('type', 'Finding')}",
                "title_link": f.get("url", ""),
                "text": f.get("detail", "")[:500],
                "fields": [
                    {"title": "URL", "value": f.get("url", ""), "short": False},
                    {"title": "Parameter", "value": f.get("parameter", "N/A"), "short": True},
                    {"title": "CVSS", "value": str(f.get("_cvss", 0.0)), "short": True},
                ],
                "footer": "Durpie Scanner",
                "ts": int(datetime.now().timestamp()),
            }]
        }

    def _discord_payload(self, f: dict) -> dict:
        sev = f.get("severity", "INFO").upper()
        int_color = int(SEVERITY_BADGE.get(sev, "#95a5a6").lstrip("#"), 16)
        return {
            "embeds": [{
                "title": f"[{sev}] {f.get('type', 'Finding')}",
                "description": f.get("detail", "")[:2000],
                "color": int_color,
                "fields": [
                    {"name": "URL", "value": f.get("url", "N/A"), "inline": False},
                    {"name": "Parameter", "value": f.get("parameter", "N/A") or "N/A", "inline": True},
                    {"name": "CVSS", "value": str(f.get("_cvss", 0.0)), "inline": True},
                ],
                "footer": {"text": "Durpie Scanner"},
            }]
        }

    def notify_finding(self, f: dict) -> bool:
        ok = True
        if self.slack_url:
            ok &= self._post(self.slack_url, self._slack_payload(f))
        if self.discord_url:
            ok &= self._post(self.discord_url, self._discord_payload(f))
        return ok

    def notify_batch(
        self, findings: List[dict], min_severity: str = "HIGH"
    ) -> Tuple[int, int]:
        """Notify all findings at or above min_severity. Returns (sent, failed)."""
        rank = _sev_rank(min_severity)
        sent = failed = 0
        for f in findings:
            if _sev_rank(f.get("severity", "INFO")) <= rank:
                if self.notify_finding(f):
                    sent += 1
                else:
                    failed += 1
        return sent, failed


# ============================================================
# GitHub Integration
# ============================================================

class GitHubIntegration:
    """Create GitHub issues for findings using the REST API."""

    API_BASE = "https://api.github.com"

    def __init__(self, token: str, repo: str):
        self.token = token
        self.repo = repo  # "owner/repo"

    def _request(self, method: str, path: str, body: dict = None) -> Optional[dict]:
        url = f"{self.API_BASE}{path}"
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode(errors="replace")
            print(f"[warn] GitHub API {exc.code}: {body_text[:200]}", file=sys.stderr)
            return None
        except Exception as exc:
            print(f"[warn] GitHub API error: {exc}", file=sys.stderr)
            return None

    def _ensure_label(self, name: str, color: str, description: str = ""):
        """Create label if it doesn't exist."""
        self._request("POST", f"/repos/{self.repo}/labels", {
            "name": name, "color": color.lstrip("#"), "description": description
        })

    def create_issue(
        self, f: dict, label_prefix: str = "durpie"
    ) -> Optional[str]:
        """Create a GitHub issue for a finding. Returns issue URL or None."""
        sev = f.get("severity", "INFO").upper()
        sev_label = f"{label_prefix}:{sev.lower()}"
        self._ensure_label(sev_label, SEVERITY_BADGE.get(sev, "#95a5a6"))
        self._ensure_label(label_prefix, "#2d3250", "Durpie security finding")

        rem = get_remediation(f.get("type", ""))
        refs_md = "\n".join(f"- {r}" for r in rem.get("refs", []))
        body = (
            f"## [{sev}] {f.get('type', 'Security Finding')}\n\n"
            f"**URL:** `{f.get('url', 'N/A')}`  \n"
            f"**Parameter:** `{f.get('parameter', 'N/A') or 'N/A'}`  \n"
            f"**CVSS v3.1:** {f.get('_cvss', 0.0):.1f} — `{f.get('_cvss_vector', 'N/A')}`\n\n"
            f"### Detail\n```\n{f.get('detail', '')[:2000]}\n```\n\n"
            + (f"### Evidence\n```\n{f.get('evidence', '')[:500]}\n```\n\n" if f.get("evidence") else "")
            + f"### Remediation\n{rem.get('fix', '')}\n\n"
            + (f"### References\n{refs_md}\n\n" if refs_md else "")
            + f"---\n*Generated by Durpie — finding hash: `{f.get('_hash', 'N/A')}`*"
        )
        result = self._request(
            "POST", f"/repos/{self.repo}/issues",
            {
                "title": f"[{sev}] {f.get('type', 'Security Finding')} @ {f.get('url', '')[:80]}",
                "body": body,
                "labels": [label_prefix, sev_label],
            },
        )
        if result:
            url = result.get("html_url", "")
            print(f"  Created: {url}")
            return url
        return None

    def create_issues_batch(
        self, findings: List[dict], min_severity: str = "HIGH"
    ) -> Tuple[int, int]:
        rank = _sev_rank(min_severity)
        created = failed = 0
        for f in findings:
            if _sev_rank(f.get("severity", "INFO")) <= rank:
                url = self.create_issue(f)
                if url:
                    created += 1
                else:
                    failed += 1
        return created, failed


# ============================================================
# Report Engine — orchestrator
# ============================================================

class ReportEngine:
    """Top-level façade. Loads findings and dispatches to all reporters."""

    def __init__(self, state_file: str = "durpie_findings_state.json"):
        self.store = FindingStore(state_file)
        self.store.load_state()

    def load(self, patterns: List[str] = None) -> Tuple[int, int]:
        """Glob for Durpie JSON files and load them. Returns (loaded, dupes)."""
        if patterns is None:
            patterns = ["durpie_*.json"]
        paths: List[str] = []
        for p in patterns:
            paths.extend(sorted(glob.glob(p)))
        return self.store.load_json_files(paths)

    def html(self, output: str = "durpie_report.html", min_severity: str = "INFO") -> str:
        r = HTMLReporter()
        return r.generate(self.store, output, min_severity=min_severity)

    def burp_export(self, output: str = "durpie_burp.xml") -> str:
        return BurpExporter().export(self.store.active(), output)

    def burp_import(self, xml_path: str) -> int:
        findings = BurpExporter().import_burp(xml_path)
        loaded, _ = self.store.load_json_files([])  # just trigger the machinery
        # Directly inject
        for f in findings:
            h = self.store._hash(f)
            if h not in self.store._hashes:
                self.store._hashes.add(h)
                f["_hash"] = h
                f["_source"] = os.path.basename(xml_path)
                f["_scanner"] = "burp-import"
                f["_cvss"] = CVSSv3Calculator.score(f.get("severity", "INFO"))
                f["_cvss_vector"] = CVSSv3Calculator.vector(f.get("severity", "INFO"))
                f["_remediation"] = get_remediation(f.get("type", ""))
                self.store.findings.append(f)
        return len(findings)

    def nuclei(self, output_dir: str = "durpie-nuclei-templates") -> List[str]:
        return NucleiExporter().generate_templates(self.store.active(), output_dir)

    def junit(
        self, output: str = "durpie_junit.xml", fail_on: str = "HIGH"
    ) -> Tuple[str, int]:
        return JUnitExporter().export(self.store.active(), output, fail_on)

    def notify(
        self, slack_url: str = None, discord_url: str = None, min_severity: str = "HIGH"
    ) -> Tuple[int, int]:
        notifier = WebhookNotifier(slack_url, discord_url)
        return notifier.notify_batch(self.store.active(), min_severity)

    def github(
        self, token: str, repo: str, min_severity: str = "HIGH"
    ) -> Tuple[int, int]:
        gh = GitHubIntegration(token, repo)
        return gh.create_issues_batch(self.store.active(), min_severity)

    def list_findings(self, status_filter: str = None) -> List[dict]:
        findings = self.store.active()
        if status_filter:
            findings = [
                f for f in findings
                if self.store.get_status(f.get("_hash", "")) == status_filter
            ]
        return findings

    def set_status(self, finding_hash: str, status: str, notes: str = ""):
        self.store.set_status(finding_hash, status, notes)


# ============================================================
# CLI
# ============================================================

def _load_engine(args: List[str]) -> "ReportEngine":
    engine = ReportEngine()
    loaded, dupes = engine.load()
    print(f"[*] Loaded {loaded} finding(s) ({dupes} deduplicated) from durpie_*.json")
    return engine


def main(argv: List[str]):
    if len(argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = argv[1].lower()

    if cmd == "report":
        out = _arg(argv, "--out", "durpie_report.html")
        min_sev = _arg(argv, "--min-severity", "INFO").upper()
        engine = _load_engine(argv)
        path = engine.html(out, min_severity=min_sev)
        print(f"[+] HTML report → {path}")

    elif cmd == "burp":
        if len(argv) > 2 and not argv[2].startswith("--"):
            # import mode
            xml_in = argv[2]
            engine = ReportEngine()
            n = engine.burp_import(xml_in)
            print(f"[+] Imported {n} finding(s) from {xml_in}")
        else:
            # export mode
            out = _arg(argv, "--out", "durpie_burp.xml")
            engine = _load_engine(argv)
            path = engine.burp_export(out)
            print(f"[+] Burp XML → {path}")

    elif cmd == "nuclei":
        out_dir = _arg(argv, "--out-dir", "durpie-nuclei-templates")
        engine = _load_engine(argv)
        paths = engine.nuclei(out_dir)
        print(f"[+] Generated {len(paths)} Nuclei template(s) → {out_dir}/")

    elif cmd == "junit":
        out = _arg(argv, "--out", "durpie_junit.xml")
        fail_on = _arg(argv, "--fail-on", "HIGH").upper()
        engine = _load_engine(argv)
        path, code = engine.junit(out, fail_on)
        print(f"[+] JUnit XML → {path} (exit code: {code})")
        sys.exit(code)

    elif cmd == "notify":
        slack = _arg(argv, "--slack", None)
        discord = _arg(argv, "--discord", None)
        min_sev = _arg(argv, "--min-severity", "HIGH").upper()
        if not slack and not discord:
            print("Error: provide --slack <url> and/or --discord <url>")
            sys.exit(1)
        engine = _load_engine(argv)
        sent, failed = engine.notify(slack, discord, min_sev)
        print(f"[+] Notifications: {sent} sent, {failed} failed")

    elif cmd == "github":
        token = _arg(argv, "--token", None)
        repo = _arg(argv, "--repo", None)
        min_sev = _arg(argv, "--min-severity", "HIGH").upper()
        if not token or not repo:
            print("Error: --token and --repo are required")
            sys.exit(1)
        engine = _load_engine(argv)
        created, failed = engine.github(token, repo, min_sev)
        print(f"[+] GitHub issues: {created} created, {failed} failed")

    elif cmd == "list":
        status_filter = _arg(argv, "--status", None)
        engine = _load_engine(argv)
        findings = engine.list_findings(status_filter)
        findings.sort(key=lambda f: _sev_rank(f.get("severity", "INFO")))
        for f in findings:
            h = f.get("_hash", "?")
            status = engine.store.get_status(h)
            print(
                f"  [{f.get('severity','?'):8}] {f.get('type','?'):<45} "
                f"hash={h}  status={status}"
            )
            print(f"           {f.get('url','')}")
        print(f"\n  Total: {len(findings)}")

    elif cmd == "verify":
        if len(argv) < 4:
            print("Usage: reporter.py verify <hash> <confirmed|false_positive|fixed> [--notes '...']")
            sys.exit(1)
        h = argv[2]
        status = argv[3]
        notes = _arg(argv, "--notes", "")
        engine = ReportEngine()
        engine.store.load_state()
        engine.set_status(h, status, notes)
        print(f"[+] {h} → {status}")

    else:
        print(f"Unknown command: {cmd!r}")
        print("Commands: report | burp | nuclei | junit | notify | github | list | verify")
        sys.exit(1)


def _arg(argv: List[str], flag: str, default):
    try:
        idx = argv.index(flag)
        return argv[idx + 1]
    except (ValueError, IndexError):
        return default


if __name__ == "__main__":
    main(sys.argv)
