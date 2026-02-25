#!/usr/bin/env python3
"""
infra_scanner.py — Phase 6 Infrastructure Scanner for Durpie
=============================================================
Subdomain enumeration, port scanning, and CMS detection.

Usage (mitmproxy addon):
    mitmdump -s infra_scanner.py

Usage (standalone):
    # Subdomain enum
    python infra_scanner.py subdomains example.com

    # Port scan
    python infra_scanner.py portscan 192.168.1.1

    # CMS detection
    python infra_scanner.py cms https://example.com

Authorized security testing only.
"""

import asyncio
import json
import re
import socket
import subprocess
import sys
import urllib.request
import urllib.error
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    from mitmproxy import ctx
    from mitmproxy.http import HTTPFlow
    _IN_MITMPROXY = True
except ImportError:
    _IN_MITMPROXY = False


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def _mlog(module: str, msg: str, level: str = "info"):
    if _IN_MITMPROXY:
        fn = getattr(ctx.log, level, ctx.log.info)
        fn(f"[Durpie:{module}] {msg}")
    else:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}][{module}] {msg}")


# ---------------------------------------------------------------------------
# Shared dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    type: str
    severity: str      # INFO / LOW / MEDIUM / HIGH / CRITICAL
    url: str
    detail: str
    evidence: str = ""
    parameter: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def __str__(self):
        return f"[{self.severity}] {self.type} @ {self.url}"


# ---------------------------------------------------------------------------
# Phase 6-A: Subdomain Enumerator
# ---------------------------------------------------------------------------

class SubdomainEnumerator:
    """DNS brute force + certificate transparency logs + external tool integration."""

    WORDLIST = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin", "portal",
        "api", "api2", "v1", "v2", "v3", "dev", "staging", "stage", "test", "qa",
        "uat", "prod", "production", "demo", "beta", "alpha", "preview", "sandbox",
        "shop", "store", "blog", "forum", "wiki", "docs", "help", "support", "cdn",
        "static", "assets", "media", "images", "img", "files", "upload", "uploads",
        "download", "downloads", "app", "apps", "mobile", "m", "wap", "secure",
        "ssl", "vpn", "remote", "rdp", "ssh", "git", "svn", "jenkins", "jira",
        "confluence", "gitlab", "github", "bitbucket", "sonar", "grafana", "kibana",
        "elastic", "kafka", "redis", "db", "database", "mysql", "postgres", "mongo",
        "internal", "intranet", "extranet", "corp", "corporate", "office",
        "auth", "login", "sso", "oauth", "id", "identity", "accounts", "account",
        "payment", "payments", "checkout", "billing", "invoice", "crm", "erp",
        "hr", "finance", "reporting", "reports", "analytics", "metrics", "monitor",
        "monitoring", "status", "health", "ops", "devops", "infra", "infrastructure",
        "cloud", "aws", "gcp", "azure", "k8s", "kubernetes", "docker", "registry",
        "mx", "ns", "ns1", "ns2", "smtp1", "smtp2", "mail2", "mail3",
        "webdav", "exchange", "autodiscover", "autoconfig", "owa",
        "management", "manage", "panel", "dashboard", "console", "control",
        "cpanel", "whm", "plesk", "webmin", "directadmin",
        "proxy", "gateway", "lb", "loadbalancer", "waf", "firewall",
        "backup", "backups", "archive", "old", "new", "legacy", "classic",
        "search", "solr", "elastic2", "logstash", "fluentd",
        "chat", "slack", "teams", "zoom", "meet", "video",
        "partner", "partners", "vendor", "suppliers", "affiliate",
        "en", "fr", "de", "es", "pt", "it", "ru", "jp", "cn", "kr",
        "us", "uk", "eu", "au", "ca", "in",
    ]

    def __init__(self):
        self.findings: List[Finding] = []
        self._seen: Set[str] = set()

    async def dns_bruteforce(self, domain: str, concurrency: int = 50) -> List[str]:
        """Async DNS brute force via thread pool (uses stdlib socket)."""
        loop = asyncio.get_event_loop()
        found: List[str] = []
        sem = asyncio.Semaphore(concurrency)

        async def probe(sub: str):
            fqdn = f"{sub}.{domain}"
            async with sem:
                try:
                    await loop.run_in_executor(
                        None, socket.getaddrinfo, fqdn, None
                    )
                    found.append(fqdn)
                    _mlog("Subdomains", f"  Found: {fqdn}", "debug" if _IN_MITMPROXY else "info")
                except (socket.gaierror, OSError):
                    pass

        await asyncio.gather(*[probe(s) for s in self.WORDLIST])
        return found

    async def crt_sh_lookup(self, domain: str) -> List[str]:
        """Query crt.sh certificate transparency logs (JSON API)."""
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        names: Set[str] = set()

        async def _fetch_aiohttp():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=20),
                        ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            _parse_crtsh(data)
            except Exception as exc:
                _mlog("Subdomains", f"crt.sh aiohttp error: {exc}", "warn")

        def _fetch_stdlib():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Durpie/2.0"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    data = json.loads(resp.read())
                    _parse_crtsh(data)
            except Exception as exc:
                _mlog("Subdomains", f"crt.sh stdlib error: {exc}", "warn")

        def _parse_crtsh(data):
            if not isinstance(data, list):
                return
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        names.add(name)

        if HAS_AIOHTTP:
            await _fetch_aiohttp()
        else:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _fetch_stdlib)

        return list(names)

    def _run_external_tool(self, tool: str, domain: str) -> List[str]:
        """Run subfinder or amass if installed."""
        try:
            if tool == "subfinder":
                cmd = [tool, "-d", domain, "-silent"]
            else:  # amass
                cmd = [tool, "enum", "-d", domain, "-silent", "-passive"]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            return [l.strip() for l in result.stdout.splitlines() if l.strip()]
        except FileNotFoundError:
            return []  # tool not installed
        except (subprocess.TimeoutExpired, Exception) as exc:
            _mlog("Subdomains", f"{tool} error: {exc}", "warn")
            return []

    async def enumerate(self, domain: str) -> List[Finding]:
        """Full enumeration: CT logs + DNS bruteforce + external tools."""
        if domain in self._seen:
            return []
        self._seen.add(domain)

        _mlog("Subdomains", f"Enumerating subdomains for: {domain}")
        found: Set[str] = set()

        # 1. Certificate transparency (fast, passive)
        ct_subs = await self.crt_sh_lookup(domain)
        found.update(ct_subs)
        _mlog("Subdomains", f"CT logs: {len(ct_subs)} results")

        # 2. DNS brute force
        dns_subs = await self.dns_bruteforce(domain)
        found.update(dns_subs)
        _mlog("Subdomains", f"DNS brute: {len(dns_subs)} results")

        # 3. External tools (opportunistic — don't fail if absent)
        loop = asyncio.get_event_loop()
        for tool in ("subfinder", "amass"):
            ext = await loop.run_in_executor(
                None, self._run_external_tool, tool, domain
            )
            if ext:
                _mlog("Subdomains", f"{tool}: {len(ext)} results")
                found.update(ext)

        # Build findings
        new_findings: List[Finding] = []
        for sub in sorted(found):
            # Try to resolve to get IP addresses for evidence
            try:
                addrs = socket.getaddrinfo(sub, None)
                ips = list({a[4][0] for a in addrs})
                evidence = f"Resolves to: {', '.join(ips[:3])}"
            except Exception:
                evidence = sub

            f = Finding(
                type="Subdomain Discovered",
                severity="INFO",
                url=f"https://{sub}",
                detail=(
                    f"Subdomain '{sub}' discovered under {domain}. "
                    f"Expand attack surface: check for forgotten dev/staging instances, "
                    f"VHOST injection, subdomain takeover."
                ),
                evidence=evidence,
                parameter=sub,
            )
            new_findings.append(f)
            self.findings.append(f)

        _mlog("Subdomains", f"Total unique subdomains found: {len(new_findings)}")
        return new_findings


# ---------------------------------------------------------------------------
# Phase 6-B: Port Scanner
# ---------------------------------------------------------------------------

class PortScanner:
    """Async TCP connect scanner with banner grabbing and service fingerprinting."""

    COMMON_PORTS: Dict[int, str] = {
        21:    "FTP",
        22:    "SSH",
        23:    "Telnet",
        25:    "SMTP",
        53:    "DNS",
        80:    "HTTP",
        110:   "POP3",
        111:   "RPC/portmapper",
        135:   "MSRPC",
        139:   "NetBIOS-SSN",
        143:   "IMAP",
        389:   "LDAP",
        443:   "HTTPS",
        445:   "SMB",
        465:   "SMTPS",
        587:   "SMTP submission",
        636:   "LDAPS",
        993:   "IMAPS",
        995:   "POP3S",
        1433:  "MSSQL",
        1521:  "Oracle DB",
        2049:  "NFS",
        2375:  "Docker daemon (unauthenticated)",
        2376:  "Docker daemon (TLS)",
        3000:  "Grafana/Dev server",
        3306:  "MySQL/MariaDB",
        3389:  "RDP",
        4848:  "GlassFish admin",
        5432:  "PostgreSQL",
        5601:  "Kibana",
        5672:  "RabbitMQ",
        5900:  "VNC",
        5984:  "CouchDB",
        6379:  "Redis",
        6443:  "Kubernetes API",
        7474:  "Neo4j",
        8080:  "HTTP-Alt",
        8443:  "HTTPS-Alt",
        8500:  "Consul",
        8888:  "Jupyter Notebook",
        9000:  "SonarQube/PHP-FPM",
        9090:  "Prometheus",
        9200:  "Elasticsearch HTTP",
        9300:  "Elasticsearch transport",
        10250: "Kubernetes kubelet",
        27017: "MongoDB",
        27018: "MongoDB shard",
        50070: "Hadoop NameNode",
    }

    # Ports where open = likely high-severity finding
    HIGH_RISK_PORTS = {
        21, 23, 2375, 3389, 4848, 5900, 6379, 8888,
        9200, 10250, 27017, 50070,
    }

    def __init__(self):
        self.findings: List[Finding] = []

    async def scan_port(
        self, host: str, port: int, timeout: float = 2.0
    ) -> Tuple[bool, str]:
        """TCP connect + banner read. Returns (is_open, banner)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            banner = ""
            try:
                # Some services push banners immediately (FTP, SSH, SMTP…)
                banner_bytes = await asyncio.wait_for(reader.read(512), timeout=1.0)
                banner = banner_bytes.decode(errors="replace").strip()
            except asyncio.TimeoutError:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            return True, banner
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False, ""

    def fingerprint_service(self, port: int, banner: str) -> str:
        """Refine service name using banner content."""
        base = self.COMMON_PORTS.get(port, "Unknown")
        if not banner:
            return base
        b = banner[:120]
        if "SSH-" in b:
            return f"SSH  ({b.split(chr(10))[0][:60]})"
        if re.search(r'^220[ -]', b) and "FTP" in b.upper():
            return f"FTP  ({b[:60]})"
        if re.search(r'^220[ -]', b):
            return f"SMTP ({b[:60]})"
        if "HTTP/" in b:
            first_line = b.split("\n")[0]
            return f"HTTP ({first_line[:60]})"
        if "+OK" in b:
            return f"POP3 ({b[:60]})"
        if "* OK" in b:
            return f"IMAP ({b[:60]})"
        if "-ERR" in b or "redis_version" in b or "+PONG" in b:
            return f"Redis ({b[:40]})"
        if "MongoDB" in b or b.startswith("\x16\x03"):
            return f"MongoDB ({b[:40]})"
        return f"{base} ({b[:40]})"

    async def scan_host(
        self,
        host: str,
        ports: List[int] = None,
        concurrency: int = 100,
        timeout: float = 2.0,
    ) -> List[Finding]:
        """Scan a host. Default: all COMMON_PORTS."""
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())

        _mlog("PortScan", f"Scanning {host} ({len(ports)} ports, concurrency={concurrency})")
        sem = asyncio.Semaphore(concurrency)
        findings: List[Finding] = []

        async def probe(port: int):
            async with sem:
                is_open, banner = await self.scan_port(host, port, timeout)
                if is_open:
                    service = self.fingerprint_service(port, banner)
                    severity = "HIGH" if port in self.HIGH_RISK_PORTS else "INFO"
                    svc_name = self.COMMON_PORTS.get(port, "Unknown")

                    detail_lines = [f"Port {port}/tcp OPEN on {host}: {svc_name}"]
                    if port in self.HIGH_RISK_PORTS:
                        detail_lines.append(
                            f"⚠  High-risk service. Verify authentication, encryption, and exposure."
                        )
                    if banner:
                        detail_lines.append(f"Banner: {banner[:200]}")
                    detail_lines.append(f"Service fingerprint: {service}")

                    f = Finding(
                        type="Open Port",
                        severity=severity,
                        url=f"tcp://{host}:{port}",
                        detail="\n".join(detail_lines),
                        evidence=banner[:100] if banner else f"{host}:{port} open",
                        parameter=str(port),
                    )
                    findings.append(f)
                    self.findings.append(f)
                    _mlog("PortScan", f"  {host}:{port}/tcp OPEN  [{service}]")

        await asyncio.gather(*[probe(p) for p in ports])
        findings.sort(key=lambda x: int(x.parameter))
        _mlog("PortScan", f"Scan complete: {len(findings)} open port(s) on {host}")
        return findings


# ---------------------------------------------------------------------------
# Phase 6-C: CMS Detector
# ---------------------------------------------------------------------------

class CMSDetector:
    """
    Detect CMS/platform via active path probing and passive header/body analysis.
    Covers: WordPress, Drupal, Joomla, Magento, and generic tech disclosure.
    """

    # --- WordPress ---
    WP_PATHS = [
        "/wp-login.php",
        "/wp-admin/",
        "/wp-json/wp/v2/",
        "/xmlrpc.php",
        "/wp-content/themes/",
        "/wp-includes/js/jquery/jquery.min.js",
    ]
    WP_VERSION_PATHS = ["/readme.html", "/?feed=rss2", "/feed/"]
    COMMON_WP_PLUGINS = [
        "woocommerce", "contact-form-7", "yoast-seo", "wordfence",
        "elementor", "wp-super-cache", "akismet", "jetpack",
        "all-in-one-seo-pack", "wp-rocket", "advanced-custom-fields",
        "updraftplus", "really-simple-ssl", "redirection",
        "wp-file-manager",  # CVE-2020-25213 (unauthenticated RCE)
    ]

    # --- Drupal ---
    DRUPAL_PATHS = [
        "/misc/drupal.js",
        "/sites/default/files/",
        "/core/misc/drupal.js",
        "/CHANGELOG.txt",
        "/core/CHANGELOG.txt",
    ]

    # --- Joomla ---
    JOOMLA_PATHS = [
        "/administrator/",
        "/components/com_content/",
        "/language/en-GB/en-GB.xml",
        "/libraries/joomla/",
        "/media/jui/js/jquery.min.js",
    ]

    # --- Magento ---
    MAGENTO_PATHS = [
        "/skin/frontend/",
        "/js/mage/",
        "/downloader/",
        "/magento_version",
        "/app/etc/local.xml",
        "/index.php/admin/",
    ]

    # --- Known vulnerable versions ---
    VULN_VERSIONS: Dict[str, Dict[str, List[str]]] = {
        "wordpress": {
            "6.4": ["CVE-2023-6553 (RCE via Backup Migration plugin)"],
            "6.3": ["CVE-2023-38000 (Contributor+ stored XSS)"],
            "5.0": ["CVE-2019-8942 (Author+ arbitrary file delete → RCE)"],
            "4.9": ["CVE-2018-6389 (DoS via load-scripts.php)"],
            "4.7": [
                "CVE-2017-1001000 (REST API unauthenticated privilege escalation)",
                "CVE-2017-5487 (User enumeration via REST API)",
            ],
            "4.6": ["CVE-2016-10033 (PHPMailer RCE)"],
            "4.2": ["CVE-2015-3440 (Stored XSS — unauthenticated)"],
        },
        "drupal": {
            "7": [
                "CVE-2014-3704 (Drupalgeddon SQLi → RCE)",
                "CVE-2018-7600 (Drupalgeddon2 RCE — unauthenticated)",
            ],
            "8": ["CVE-2018-7600 (Drupalgeddon2 RCE)", "CVE-2018-7602 (RCE)"],
            "9.0": ["CVE-2020-13664 (RCE — specific configs)"],
            "9.3": ["CVE-2022-25271 (SA-CORE-2022-003)"],
        },
        "joomla": {
            "3.4": ["CVE-2015-8562 (PHP Object Injection → RCE — unauthenticated)"],
            "3.2": ["CVE-2015-8562"],
            "1.5": ["CVE-2012-1563 (multiple)"],
        },
        "magento": {
            "2.3": ["CVE-2019-7139 (SQLi → RCE)", "CVE-2022-24086 (Pre-auth RCE)"],
            "2.4": ["CVE-2022-24086 (Pre-auth RCE — Magento 2.4.3 and below)"],
            "1.9": ["CVE-2016-4010 (PHP Object Injection)"],
        },
    }

    def __init__(self):
        self.findings: List[Finding] = []
        self._scanned: Set[str] = set()

    async def _probe_paths(
        self, session, base: str, paths: List[str], timeout: float = 5.0
    ) -> Dict[str, int]:
        """Return {path: status_code} for non-404 responses."""
        hits: Dict[str, int] = {}

        async def probe(path: str):
            try:
                url = base.rstrip("/") + path
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=False,
                    ssl=False,
                ) as resp:
                    if resp.status not in (404, 410, 400):
                        hits[path] = resp.status
            except Exception:
                pass

        await asyncio.gather(*[probe(p) for p in paths])
        return hits

    def _check_vuln_version(self, cms: str, version: str) -> List[str]:
        """Return CVE strings for known vulnerable versions (prefix match)."""
        cves: List[str] = []
        for v_prefix, v_cves in self.VULN_VERSIONS.get(cms, {}).items():
            if version.startswith(v_prefix):
                cves.extend(v_cves)
        return cves

    async def _extract_wp_version(self, session, base: str) -> Optional[str]:
        for path in self.WP_VERSION_PATHS:
            try:
                url = base.rstrip("/") + path
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5), ssl=False
                ) as resp:
                    text = await resp.text(errors="replace")
                    m = re.search(
                        r'(?:WordPress\s+|<generator>https://wordpress\.org/\?v=)(\d+\.\d+(?:\.\d+)?)',
                        text, re.IGNORECASE
                    )
                    if m:
                        return m.group(1)
            except Exception:
                pass
        return None

    async def _enumerate_wp_plugins(self, session, base: str) -> List[str]:
        found: List[str] = []

        async def probe(plugin: str):
            try:
                url = f"{base.rstrip('/')}/wp-content/plugins/{plugin}/"
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=3),
                    allow_redirects=False, ssl=False
                ) as resp:
                    if resp.status in (200, 403):  # 403 = exists but listing disabled
                        found.append(plugin)
            except Exception:
                pass

        await asyncio.gather(*[probe(p) for p in self.COMMON_WP_PLUGINS])
        return found

    async def _check_headers_and_meta(self, session, base: str) -> List[Finding]:
        """Passive: grab homepage and check disclosure headers/meta tags."""
        disc_findings: List[Finding] = []
        try:
            async with session.get(
                base, timeout=aiohttp.ClientTimeout(total=8), ssl=False
            ) as resp:
                headers = dict(resp.headers)
                text = await resp.text(errors="replace")

                # Generator meta tag
                m = re.search(
                    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                    text, re.IGNORECASE
                )
                if not m:
                    m = re.search(
                        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
                        text, re.IGNORECASE
                    )
                if m:
                    gen = m.group(1).strip()
                    disc_findings.append(Finding(
                        type="Technology Disclosure",
                        severity="INFO",
                        url=base,
                        detail=f"Generator meta tag reveals technology: {gen}",
                        evidence=f'<meta name="generator" content="{gen}">',
                    ))

                # Disclosure response headers
                for hdr in (
                    "X-Powered-By", "X-Generator", "X-CMS",
                    "X-Drupal-Cache", "X-WordPress-Encoding",
                    "X-AspNet-Version", "X-AspNetMvc-Version",
                    "Server",
                ):
                    if hdr in headers:
                        val = headers[hdr]
                        # Only flag Server if it includes version
                        if hdr == "Server" and not re.search(r'\d', val):
                            continue
                        disc_findings.append(Finding(
                            type="Technology Disclosure",
                            severity="INFO",
                            url=base,
                            detail=(
                                f"Response header '{hdr}' discloses technology: {val}"
                            ),
                            evidence=f"{hdr}: {val}",
                        ))
        except Exception:
            pass
        return disc_findings

    async def detect(self, base_url: str) -> List[Finding]:
        """Active + passive CMS detection for base_url."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base in self._scanned:
            return []
        self._scanned.add(base)

        _mlog("CMS", f"Detecting CMS at: {base}")
        all_findings: List[Finding] = []

        if not HAS_AIOHTTP:
            _mlog("CMS", "aiohttp not available — CMS detection disabled", "warn")
            return []

        async with aiohttp.ClientSession(
            headers={"User-Agent": "Mozilla/5.0 (compatible; Durpie/2.0)"}
        ) as session:
            # --- WordPress ---
            wp_hits = await self._probe_paths(session, base, self.WP_PATHS)
            if len(wp_hits) >= 2:
                version = await self._extract_wp_version(session, base)
                plugins = await self._enumerate_wp_plugins(session, base)
                cves = self._check_vuln_version("wordpress", version or "")

                lines = [f"WordPress detected at {base}"]
                if version:
                    lines.append(f"Version: {version}")
                if plugins:
                    lines.append(f"Plugins found: {', '.join(plugins)}")
                if cves:
                    lines.append(f"Known CVEs for v{version}:")
                    for c in cves:
                        lines.append(f"  • {c}")

                f = Finding(
                    type="CMS Detected — WordPress",
                    severity="HIGH" if cves else "MEDIUM",
                    url=base,
                    detail="\n".join(lines),
                    evidence=", ".join(wp_hits.keys()),
                )
                all_findings.append(f)
                self.findings.append(f)
                _mlog("CMS", f"WordPress detected (v{version or 'unknown'}), {len(plugins)} plugin(s), {len(cves)} CVE(s)")

            # --- Drupal ---
            drupal_hits = await self._probe_paths(session, base, self.DRUPAL_PATHS)
            if drupal_hits:
                version = None
                for chlog in ("/CHANGELOG.txt", "/core/CHANGELOG.txt"):
                    try:
                        async with session.get(
                            base.rstrip("/") + chlog,
                            timeout=aiohttp.ClientTimeout(total=5), ssl=False
                        ) as resp:
                            if resp.status == 200:
                                text = await resp.text(errors="replace")
                                m = re.search(r'Drupal (\d+\.\d+(?:\.\d+)?)', text)
                                if m:
                                    version = m.group(1)
                                    break
                    except Exception:
                        pass

                cves = self._check_vuln_version("drupal", version or "")
                lines = [f"Drupal CMS detected at {base}"]
                if version:
                    lines.append(f"Version: {version}")
                if cves:
                    lines.append("Known CVEs:")
                    for c in cves:
                        lines.append(f"  • {c}")

                f = Finding(
                    type="CMS Detected — Drupal",
                    severity="HIGH" if cves else "MEDIUM",
                    url=base,
                    detail="\n".join(lines),
                    evidence=", ".join(drupal_hits.keys()),
                )
                all_findings.append(f)
                self.findings.append(f)
                _mlog("CMS", f"Drupal detected (v{version or 'unknown'}), {len(cves)} CVE(s)")

            # --- Joomla ---
            joomla_hits = await self._probe_paths(session, base, self.JOOMLA_PATHS)
            if len(joomla_hits) >= 2:
                version = None
                try:
                    async with session.get(
                        base.rstrip("/") + "/language/en-GB/en-GB.xml",
                        timeout=aiohttp.ClientTimeout(total=5), ssl=False
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors="replace")
                            m = re.search(r'<version>(\d+\.\d+(?:\.\d+)?)</version>', text)
                            if m:
                                version = m.group(1)
                except Exception:
                    pass

                cves = self._check_vuln_version("joomla", version or "")
                lines = [f"Joomla CMS detected at {base}"]
                if version:
                    lines.append(f"Version: {version}")
                if cves:
                    lines.append("Known CVEs:")
                    for c in cves:
                        lines.append(f"  • {c}")

                f = Finding(
                    type="CMS Detected — Joomla",
                    severity="HIGH" if cves else "MEDIUM",
                    url=base,
                    detail="\n".join(lines),
                    evidence=", ".join(joomla_hits.keys()),
                )
                all_findings.append(f)
                self.findings.append(f)
                _mlog("CMS", f"Joomla detected (v{version or 'unknown'}), {len(cves)} CVE(s)")

            # --- Magento ---
            magento_hits = await self._probe_paths(session, base, self.MAGENTO_PATHS)
            if magento_hits:
                version = None
                try:
                    async with session.get(
                        base.rstrip("/") + "/magento_version",
                        timeout=aiohttp.ClientTimeout(total=5), ssl=False
                    ) as resp:
                        if resp.status == 200:
                            version = (await resp.text(errors="replace")).strip()
                except Exception:
                    pass

                cves = self._check_vuln_version("magento", version or "")
                lines = [f"Magento e-commerce platform detected at {base}"]
                if version:
                    lines.append(f"Version: {version}")
                lines.append(
                    "Magento admin panel exposure: check /index.php/admin/ for default creds."
                )
                if cves:
                    lines.append("Known CVEs:")
                    for c in cves:
                        lines.append(f"  • {c}")

                f = Finding(
                    type="CMS Detected — Magento",
                    severity="HIGH" if cves else "MEDIUM",
                    url=base,
                    detail="\n".join(lines),
                    evidence=", ".join(magento_hits.keys()),
                )
                all_findings.append(f)
                self.findings.append(f)
                _mlog("CMS", f"Magento detected (v{version or 'unknown'}), {len(cves)} CVE(s)")

            # --- Passive header / meta disclosure ---
            disc = await self._check_headers_and_meta(session, base)
            for d in disc:
                all_findings.append(d)
                self.findings.append(d)

        return all_findings


# ---------------------------------------------------------------------------
# Phase 6 combined mitmproxy addon
# ---------------------------------------------------------------------------

class InfraScannerSuite:
    """
    mitmproxy addon combining Phase 6 infrastructure scanners.

    Triggers:
      - First time a new host is seen → subdomain enumeration + CMS detection
      - Every response → passive technology disclosure check

    Load: mitmdump -s infra_scanner.py
    """

    def __init__(self):
        self.subdomain = SubdomainEnumerator()
        self.portscan = PortScanner()
        self.cms = CMSDetector()
        self._seen_hosts: Set[str] = set()
        self.all_findings: List[Finding] = []

    def running(self):
        _mlog("Infra", "InfraScannerSuite active (Subdomain + CMS)")
        if not HAS_AIOHTTP:
            _mlog("Infra", "WARNING: aiohttp not installed — active probing disabled", "warn")

    def request(self, flow: "HTTPFlow"):
        host = flow.request.pretty_host
        if host and host not in self._seen_hosts:
            self._seen_hosts.add(host)
            scheme = flow.request.scheme or "https"
            asyncio.ensure_future(self._on_new_host(host, scheme))

    async def _on_new_host(self, host: str, scheme: str):
        base_url = f"{scheme}://{host}"

        # CMS detection
        cms_findings = await self.cms.detect(base_url)
        self.all_findings.extend(cms_findings)

        # Subdomain enumeration for the apex domain
        apex = self._apex(host)
        if apex:
            sub_findings = await self.subdomain.enumerate(apex)
            self.all_findings.extend(sub_findings)

    @staticmethod
    def _apex(host: str) -> Optional[str]:
        """Extract apex domain (last two labels) — skip IPs."""
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) or ":" in host:
            return None
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host

    def done(self):
        if not self.all_findings:
            return
        out = {
            "scanner": "InfraScannerSuite",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total": len(self.all_findings),
            "findings": [f.__dict__ for f in self.all_findings],
        }
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"durpie_infra_{ts}.json"
        with open(path, "w") as fp:
            json.dump(out, fp, indent=2)
        _mlog("Infra", f"Exported {len(self.all_findings)} findings → {path}")


# mitmproxy entry point
addons = [InfraScannerSuite()]


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def _print_findings(findings: List[Finding]):
    if not findings:
        print("  (no findings)")
        return
    for f in findings:
        icon = {"INFO": "ℹ", "LOW": "○", "MEDIUM": "◎", "HIGH": "●", "CRITICAL": "★"}.get(
            f.severity, "?"
        )
        print(f"  {icon} [{f.severity}] {f.type}")
        print(f"      URL: {f.url}")
        for line in f.detail.splitlines():
            print(f"      {line}")
        if f.evidence:
            print(f"      Evidence: {f.evidence[:120]}")
        print()


async def _main_async(argv: List[str]):
    if len(argv) < 3:
        print(__doc__)
        sys.exit(1)

    cmd = argv[1].lower()

    if cmd == "subdomains":
        domain = argv[2]
        print(f"[*] Subdomain enumeration: {domain}")
        enum = SubdomainEnumerator()
        findings = await enum.enumerate(domain)
        print(f"\n[+] {len(findings)} subdomain(s) found:\n")
        _print_findings(findings)

    elif cmd == "portscan":
        host = argv[2]
        ports = None
        if len(argv) > 3:
            try:
                ports = [int(p) for p in argv[3].split(",")]
            except ValueError:
                print("Invalid ports. Use comma-separated integers, e.g. 22,80,443")
                sys.exit(1)
        print(f"[*] Port scanning: {host}")
        scanner = PortScanner()
        findings = await scanner.scan_host(host, ports=ports)
        print(f"\n[+] {len(findings)} open port(s):\n")
        _print_findings(findings)

    elif cmd == "cms":
        url = argv[2]
        if not HAS_AIOHTTP:
            print("Error: aiohttp is required for CMS detection. pip install aiohttp")
            sys.exit(1)
        print(f"[*] CMS detection: {url}")
        detector = CMSDetector()
        findings = await detector.detect(url)
        print(f"\n[+] {len(findings)} finding(s):\n")
        _print_findings(findings)

    else:
        print(f"Unknown command: {cmd!r}")
        print("Commands: subdomains <domain> | portscan <host> [ports] | cms <url>")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(_main_async(sys.argv))
