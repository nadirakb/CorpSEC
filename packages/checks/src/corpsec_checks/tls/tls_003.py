"""TLS-003 — outdated TLS 1.0 and 1.1 are switched off."""

from __future__ import annotations

import asyncio
import ssl
from typing import ClassVar

from corpsec_checks._common import FACT_TLS, observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.tls import COMMON_SUITES, TLS1_0, TLS1_1, VERSION_NAMES, HelloResult


class LegacyTlsDisabled(Check):
    id = "TLS-003"
    version = "1.0.0"
    stage = Stage.ENCRYPTION
    requires: ClassVar[frozenset[str]] = frozenset({FACT_TLS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        host = ctx.target.host

        async def probe(version: int) -> HelloResult:
            try:
                return await ctx.tls.hello(host, version, COMMON_SUITES)
            except (OSError, ssl.SSLError):
                return HelloResult(accepted=False)

        results = await asyncio.gather(probe(TLS1_0), probe(TLS1_1))
        enabled = [
            VERSION_NAMES[v]
            for v, r in zip((TLS1_0, TLS1_1), results, strict=True)
            if r.accepted and r.version == v
        ]
        if not enabled:
            return [observe(host, Severity.PASS, "tls", observed="TLS 1.0 and 1.1 refused")]
        return [
            observe(
                host,
                Severity.MEDIUM,
                "tls",
                observed=f"{name} accepted",
                expected="Only TLS 1.2 and 1.3",
                dedupe_key=name,
            )
            for name in enabled
        ]
