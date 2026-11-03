from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
import pytest

from corpsec_scanner import Check, ScanOptions, ScanResult, Severity, run_scan
from corpsec_scanner.dns import DnsAnswer, DnsClient
from corpsec_scanner.http import HttpPolicy
from corpsec_scanner.intel import IntelSnapshot
from corpsec_scanner.tls import TlsProber

Route = httpx.Response | Callable[[httpx.Request], httpx.Response]


class FakeDns(DnsClient):
    """DNS answers from a dict: {("example.com", "TXT"): ["v=spf1 -all"]}."""

    def __init__(
        self,
        records: dict[tuple[str, str], list[str]] | None = None,
        nxdomain: set[str] | None = None,
    ) -> None:
        super().__init__(nameservers=["192.0.2.1"])
        self.records = records or {}
        self.nxdomain = nxdomain or set()

    async def _lookup(self, name: str, rdtype: str) -> DnsAnswer:
        if name in self.nxdomain:
            return DnsAnswer(records=(), nxdomain=True)
        return DnsAnswer(records=tuple(self.records.get((name, rdtype), [])))


@dataclass
class FakeSite:
    """HTTP routes keyed by ``scheme://host/path``. Anything else is a 404."""

    routes: dict[str, Route] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        route = self.routes.get(f"{req.url.scheme}://{req.url.host}{req.url.path}")
        if route is None:
            return httpx.Response(404, text="not found")
        return route(req) if callable(route) else route


def html(body: str, status: int = 200, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        status, text=body, headers={"content-type": "text/html; charset=utf-8", **(headers or {})}
    )


@pytest.fixture
def scan() -> Callable[..., object]:
    async def run(
        checks: list[Check],
        site: FakeSite | None = None,
        *,
        dns: FakeDns | None = None,
        tls: TlsProber | None = None,
        intel: IntelSnapshot | None = None,
        target: str = "example.com",
    ) -> ScanResult:
        site = site or FakeSite()
        options = ScanOptions(
            preflight=False,
            http_policy=HttpPolicy(per_host_rps=1000),
            transport_factory=lambda verify: httpx.MockTransport(site.handler),
            dns=dns or FakeDns(),
            tls=tls,
            intel=intel or IntelSnapshot(),
        )
        return await run_scan(target, checks, options=options)

    return run


def severities(result: ScanResult, check_id: str) -> list[Severity]:
    return [f.severity for f in result.findings if f.check_id == check_id]


@pytest.fixture
def mock_options() -> Callable[[Callable[[httpx.Request], httpx.Response]], ScanOptions]:
    def make(handler: Callable[[httpx.Request], httpx.Response]) -> ScanOptions:
        return ScanOptions(
            preflight=False,
            transport_factory=lambda verify: httpx.MockTransport(handler),
            dns=FakeDns(),
        )

    return make
