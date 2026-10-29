"""TLS-004 — a modern protocol (TLS 1.2 or 1.3) is supported."""

from __future__ import annotations

import ssl
from typing import ClassVar

from corpsec_checks._common import FACT_TLS, observe
from corpsec_checks.tls._cert import TlsInfo
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.tls import COMMON_SUITES, TLS1_2


class ModernTlsSupported(Check):
    id = "TLS-004"
    version = "1.0.0"
    stage = Stage.ENCRYPTION
    requires: ClassVar[frozenset[str]] = frozenset({FACT_TLS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        host = ctx.target.host
        info: TlsInfo = ctx.facts.get(FACT_TLS)
        negotiated = info.handshake.version
        if negotiated in ("TLSv1.3", "TLSv1.2"):
            supported = True
        else:
            try:
                r = await ctx.tls.hello(host, TLS1_2, COMMON_SUITES)
                supported = r.accepted and r.version == TLS1_2
            except (OSError, ssl.SSLError):
                supported = False
        return [
            observe(
                host,
                Severity.PASS if supported else Severity.HIGH,
                "tls",
                observed={"negotiated": negotiated},
                expected="TLS 1.2 or TLS 1.3",
                context={"tls13": str(negotiated == "TLSv1.3").lower()},
            )
        ]
