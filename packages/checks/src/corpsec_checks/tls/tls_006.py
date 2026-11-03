"""TLS-006 — forward secrecy: recorded traffic can't be decrypted later if the key leaks."""

from __future__ import annotations

import ssl
from typing import ClassVar

from corpsec_checks._common import FACT_TLS, observe
from corpsec_checks.tls._cert import TlsInfo
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.tls import FORWARD_SECRET_SUITES, TLS1_2


class ForwardSecrecy(Check):
    id = "TLS-006"
    version = "1.0.0"
    stage = Stage.ENCRYPTION
    requires: ClassVar[frozenset[str]] = frozenset({FACT_TLS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        host = ctx.target.host
        info: TlsInfo = ctx.facts.get(FACT_TLS)
        if info.handshake.version == "TLSv1.3":
            ok = True  # every TLS 1.3 key exchange is forward secret
        else:
            try:
                ok = (await ctx.tls.hello(host, TLS1_2, FORWARD_SECRET_SUITES)).accepted
            except (OSError, ssl.SSLError):
                ok = False
        return [
            observe(
                host,
                Severity.PASS if ok else Severity.LOW,
                "tls",
                observed={"negotiated": info.handshake.version, "forward_secrecy": ok},
                expected="ECDHE or DHE key exchange",
            )
        ]
