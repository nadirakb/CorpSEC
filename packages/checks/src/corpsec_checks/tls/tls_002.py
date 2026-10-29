"""TLS-002 — the certificate doesn't expire soon (≤14 days high, ≤3 days critical)."""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_TLS, observe
from corpsec_checks.tls._cert import TlsInfo
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


class CertificateExpiry(Check):
    id = "TLS-002"
    version = "1.0.0"
    stage = Stage.ENCRYPTION
    requires: ClassVar[frozenset[str]] = frozenset({FACT_TLS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        info: TlsInfo = ctx.facts.get(FACT_TLS)
        if info.cert is None:
            return []
        days = info.cert.days_left()
        if days <= 3:
            severity = Severity.CRITICAL
        elif days <= 14:
            severity = Severity.HIGH
        else:
            severity = Severity.PASS
        return [
            observe(
                ctx.target.host,
                severity,
                "tls",
                observed={"valid_until": info.cert.not_after.isoformat(), "days_left": days},
                expected="More than 14 days of validity left",
                context={"days_left": str(days)},
            )
        ]
