"""PORT-001 — no risky services (databases, remote desktop, file sharing) open to the internet.

CorpSEC doesn't probe ports itself (spec §5). It reads Shodan's free InternetDB, which
records what the whole internet sees on an address. Switched on per deployment (check config
``internetdb=on``) because the data's licence must fit how CorpSEC is offered. The data can be
a few days old, so findings are "likely".
"""

from __future__ import annotations

import ipaddress
import json
from typing import ClassVar

import httpx

from corpsec_checks._common import FACT_HOMEPAGE, observe
from corpsec_scanner import Check, Confidence, Observation, ScanContext, Severity, Stage
from corpsec_scanner.dns import DnsError
from corpsec_scanner.http import RequestBudgetExceededError

INTERNETDB = "https://internetdb.shodan.io/{ip}"
MAX_IPS = 2

RISKY_PORTS: dict[int, tuple[str, Severity]] = {
    21: ("file transfer (FTP)", Severity.MEDIUM),
    23: ("remote login (Telnet)", Severity.HIGH),
    445: ("Windows file sharing (SMB)", Severity.HIGH),
    1433: ("database (SQL Server)", Severity.HIGH),
    2375: ("Docker control", Severity.CRITICAL),
    3306: ("database (MySQL)", Severity.HIGH),
    3389: ("remote desktop (RDP)", Severity.HIGH),
    5432: ("database (PostgreSQL)", Severity.HIGH),
    5900: ("remote screen (VNC)", Severity.HIGH),
    5984: ("database (CouchDB)", Severity.HIGH),
    6379: ("database (Redis)", Severity.HIGH),
    9200: ("search database (Elasticsearch)", Severity.HIGH),
    11211: ("cache (Memcached)", Severity.HIGH),
    27017: ("database (MongoDB)", Severity.HIGH),
}


class RiskyOpenPorts(Check):
    id = "PORT-001"
    version = "1.0.0"
    stage = Stage.CONNECTION
    uses: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        if ctx.config.get("internetdb") != "on":
            return []
        host = ctx.target.host
        try:
            ips = [
                ip for ip in await ctx.dns.resolve(host, "A") if ipaddress.ip_address(ip).is_global
            ][:MAX_IPS]
        except DnsError:
            return []
        out: list[Observation] = []
        looked_up: list[str] = []
        for ip in ips:
            url = INTERNETDB.format(ip=ip)
            try:
                r = await ctx.external.get(url)
                data = json.loads(r.text) if r.status == 200 else {"ports": []}
            except (httpx.HTTPError, ValueError, RequestBudgetExceededError):
                continue
            if r.status not in (200, 404):  # 404: nothing known about this address
                continue
            looked_up.append(ip)
            for port in sorted(p for p in data.get("ports", []) if p in RISKY_PORTS):
                service, severity = RISKY_PORTS[port]
                out.append(
                    observe(
                        host,
                        severity,
                        "http",
                        confidence=Confidence.LIKELY,
                        query=url,
                        observed={"ip": ip, "port": port, "service": service},
                        expected="Only web ports (80, 443) open to everyone",
                        dedupe_key=f"{ip}:{port}",
                        references=["https://internetdb.shodan.io/"],
                    )
                )
        if out:
            return out
        if looked_up:
            return [observe(host, Severity.PASS, "http", observed={"ips": looked_up})]
        return []
