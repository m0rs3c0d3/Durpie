#!/usr/bin/env python3
"""
Durpie v2 - Intruder Module
===========================

Automated attack tool similar to Burp Intruder.

Usage:
    from intruder import Intruder
    
    intruder = Intruder()
    intruder.load_request_from_file("request.txt")
    intruder.set_positions(["username", "password"])
    intruder.load_payloads("wordlist.txt")
    results = await intruder.attack_sniper()
"""

import re
import json
import asyncio
import urllib.parse
from typing import List, Dict, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from itertools import product
import hashlib

# Optional async HTTP
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


@dataclass
class IntruderRequest:
    """Request template for Intruder"""
    method: str = "GET"
    url: str = ""
    host: str = ""
    port: int = 80
    is_https: bool = False
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    positions: List[str] = field(default_factory=list)


@dataclass
class IntruderResult:
    """Result of a single attack request"""
    payload: str
    position: str
    status_code: int
    response_length: int
    response_time: float
    response_body: str = ""
    error: str = ""
    timestamp: str = ""


class PayloadProcessor:
    """Transform payloads before injection"""
    
    @staticmethod
    def url_encode(payload: str) -> str:
        return urllib.parse.quote(payload, safe='')
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        import base64
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def md5_hash(payload: str) -> str:
        return hashlib.md5(payload.encode()).hexdigest()
    
    @staticmethod
    def add_prefix(payload: str, prefix: str) -> str:
        return prefix + payload
    
    @staticmethod
    def add_suffix(payload: str, suffix: str) -> str:
        return payload + suffix


class PayloadGenerator:
    """Generate attack payloads"""
    
    @staticmethod
    def numbers(start: int, end: int, step: int = 1) -> List[str]:
        return [str(i) for i in range(start, end + 1, step)]
    
    @staticmethod
    def bruteforce(charset: str, min_len: int, max_len: int) -> List[str]:
        results = []
        for length in range(min_len, max_len + 1):
            for combo in product(charset, repeat=length):
                results.append(''.join(combo))
        return results


class Intruder:
    """
    Main Intruder class.
    
    Attack types:
    - sniper: One position at a time
    - battering_ram: Same payload all positions
    - cluster_bomb: All combinations
    """
    
    def __init__(self):
        self.request: Optional[IntruderRequest] = None
        self.payloads: Dict[str, List[str]] = {}
        self.results: List[IntruderResult] = []
        self.processors: List[Callable] = []
        self.concurrent = 10
        self.timeout = 30
        self.delay = 0          # seconds between batches (rate limiting)
        self.verify_ssl = True  # verify SSL certificates
        self.callback: Optional[Callable] = None
    
    def load_request_raw(self, raw: str):
        """Parse raw HTTP request"""
        lines = raw.strip().split('\n')
        parts = lines[0].split(' ', 2)
        method, path = parts[0], parts[1]
        
        headers = {}
        body_idx = len(lines)
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_idx = i + 1
                break
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
        
        body = '\n'.join(lines[body_idx:]) if body_idx < len(lines) else ''
        host = headers.get('Host', '')
        
        self.request = IntruderRequest(
            method=method, url=path, host=host.split(':')[0],
            port=443 if ':443' in host else 80,
            is_https=':443' in host,
            headers=headers, body=body
        )
    
    def load_request_file(self, path: str):
        with open(path) as f:
            self.load_request_raw(f.read())
    
    def set_positions(self, positions: List[str]):
        if self.request:
            self.request.positions = positions
    
    def load_payloads(self, payloads: List[str], position: str = None):
        if position:
            self.payloads[position] = payloads
        elif self.request:
            for pos in self.request.positions:
                self.payloads[pos] = payloads.copy()
    
    def load_payloads_file(self, path: str, position: str = None):
        with open(path, errors='ignore') as f:
            payloads = [l.strip() for l in f if l.strip()]
        self.load_payloads(payloads, position)
    
    def _process(self, payload: str) -> str:
        for p in self.processors:
            payload = p(payload)
        return payload
    
    def _build_url(self, position: str, payload: str) -> str:
        if not self.request:
            return ""
        
        payload = self._process(payload)
        url = self.request.url
        
        # Replace markers
        url = url.replace(f"{{{position}}}", payload)
        url = url.replace(f"§{position}§", payload)
        
        # Replace in query string
        if '?' in url and f"{{{position}}}" not in self.request.url:
            base, query = url.split('?', 1)
            params = dict(p.split('=', 1) for p in query.split('&') if '=' in p)
            if position in params:
                params[position] = urllib.parse.quote(payload)
                url = base + '?' + '&'.join(f"{k}={v}" for k, v in params.items())
        
        scheme = 'https' if self.request.is_https else 'http'
        return f"{scheme}://{self.request.host}{url}"
    
    def _build_body(self, position: str, payload: str) -> str:
        if not self.request or not self.request.body:
            return ""
        
        payload = self._process(payload)
        body = self.request.body
        body = body.replace(f"{{{position}}}", payload)
        body = body.replace(f"§{position}§", payload)
        body = re.sub(f'{position}=[^&]*', f'{position}={urllib.parse.quote(payload)}', body)
        return body
    
    async def _send(self, session, position: str, payload: str) -> IntruderResult:
        url = self._build_url(position, payload)
        body = self._build_body(position, payload)
        headers = self.request.headers.copy()

        ssl_opt = None if self.verify_ssl else False
        start = datetime.now()
        try:
            async with session.request(
                self.request.method, url,
                headers=headers,
                data=body if body else None,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=ssl_opt
            ) as resp:
                text = await resp.text()
                elapsed = (datetime.now() - start).total_seconds()
                return IntruderResult(
                    payload=payload, position=position,
                    status_code=resp.status,
                    response_length=len(text),
                    response_time=elapsed,
                    response_body=text[:500],
                    timestamp=datetime.now().isoformat()
                )
        except Exception as e:
            return IntruderResult(
                payload=payload, position=position,
                status_code=0, response_length=0,
                response_time=0, error=str(e),
                timestamp=datetime.now().isoformat()
            )
    
    async def attack_sniper(self) -> List[IntruderResult]:
        """Test each position independently"""
        if not AIOHTTP_AVAILABLE:
            print("aiohttp required: pip install aiohttp")
            return []

        self.results = []
        ssl_opt = None if self.verify_ssl else False
        conn = aiohttp.TCPConnector(limit=self.concurrent, ssl=ssl_opt)

        async with aiohttp.ClientSession(connector=conn) as session:
            for position in self.request.positions:
                payloads = self.payloads.get(position, [])
                tasks = [self._send(session, position, p) for p in payloads]

                for i in range(0, len(tasks), self.concurrent):
                    batch = tasks[i:i+self.concurrent]
                    results = await asyncio.gather(*batch)
                    for r in results:
                        self.results.append(r)
                        if self.callback:
                            self.callback(r)
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)

        return self.results
    
    async def attack_battering_ram(self) -> List[IntruderResult]:
        """Same payload in all positions"""
        if not AIOHTTP_AVAILABLE:
            return []

        self.results = []
        payloads = self.payloads.get(self.request.positions[0], [])
        ssl_opt = None if self.verify_ssl else False
        conn = aiohttp.TCPConnector(limit=self.concurrent, ssl=ssl_opt)

        async with aiohttp.ClientSession(connector=conn) as session:
            for payload in payloads:
                tasks = [self._send(session, pos, payload) for pos in self.request.positions]
                results = await asyncio.gather(*tasks)
                for r in results:
                    self.results.append(r)
                    if self.callback:
                        self.callback(r)
                if self.delay > 0:
                    await asyncio.sleep(self.delay)

        return self.results
    
    def analyze(self) -> Dict:
        """Find anomalies in results"""
        if not self.results:
            return {}
        
        by_status = {}
        for r in self.results:
            by_status.setdefault(r.status_code, []).append(r)
        
        lengths = [r.response_length for r in self.results]
        avg_len = sum(lengths) / len(lengths)
        
        anomalies = []
        for r in self.results:
            if abs(r.response_length - avg_len) > avg_len * 0.2:
                anomalies.append({
                    'type': 'length_anomaly',
                    'payload': r.payload,
                    'length': r.response_length
                })
        
        return {
            'total': len(self.results),
            'by_status': {k: len(v) for k, v in by_status.items()},
            'avg_length': avg_len,
            'anomalies': anomalies
        }
    
    def export(self, path: str):
        """Export results to JSON"""
        data = [
            {
                'payload': r.payload,
                'position': r.position,
                'status': r.status_code,
                'length': r.response_length,
                'time': r.response_time
            }
            for r in self.results
        ]
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Durpie Intruder")
    parser.add_argument("-r", "--request", help="Request file")
    parser.add_argument("-p", "--payloads", help="Payload file")
    parser.add_argument("-P", "--positions", nargs="+", help="Positions to fuzz")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("-a", "--attack", choices=['sniper', 'battering_ram'], default='sniper')
    parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()
    
    if not args.request:
        print("""
Durpie Intruder - Automated Fuzzing
===================================

Usage:
  python intruder.py -r request.txt -p wordlist.txt -P username password

Example request.txt:
  POST /login HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded
  
  username={username}&password={password}

Attack types:
  --attack sniper        : Test each position independently
  --attack battering_ram : Same payload in all positions
        """)
    else:
        intruder = Intruder()
        intruder.load_request_file(args.request)
        intruder.set_positions(args.positions or [])
        
        if args.payloads:
            intruder.load_payloads_file(args.payloads)
        
        intruder.concurrent = args.threads
        
        def on_result(r):
            print(f"[{r.status_code}] {r.payload[:30]:<30} len={r.response_length}")
        
        intruder.callback = on_result
        
        print(f"Starting {args.attack} attack...")
        
        if args.attack == 'sniper':
            asyncio.run(intruder.attack_sniper())
        else:
            asyncio.run(intruder.attack_battering_ram())
        
        analysis = intruder.analyze()
        print(f"\nResults: {analysis['total']} requests")
        print(f"Status codes: {analysis['by_status']}")
        print(f"Anomalies: {len(analysis['anomalies'])}")
        
        if args.output:
            intruder.export(args.output)
            print(f"Exported to {args.output}")
