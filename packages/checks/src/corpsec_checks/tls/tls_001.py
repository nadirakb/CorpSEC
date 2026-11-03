"""TLS-001 — the certificate is valid: trusted chain, matching hostname, not expired."""

from __future__ import annotations

import ssl
from typing import ClassVar

from corpsec_checks._common import FACT_TLS, observe
from corpsec_checks.tls._cert import TlsInfo, explain_verify_error, parse_cert
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.netguard import BlockedAddressError


class CertificateValid(Check):
    id = "TLS-001"
    version = "1.0.0"
    stage = Stage.ENCRYPTION
    provides: ClassVar[frozenset[str]] = frozenset({FACT_TLS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        host = ctx.target.host
        try:
            hs = await ctx.tls.handshake(host)
        except (OSError, TimeoutError, ssl.SSLError, BlockedAddressError):
            return []  # no HTTPS at all: CONN-001 reports it
        cert = parse_cert(hs.cert_der) if hs.cert_der else None
        ctx.set_fact(FACT_TLS, TlsInfo(handshake=hs, cert=cert))
        observed: dict[str, object] = {"certificate": cert.summary() if cert else None}
        if hs.verify_error:
            observed["problem"] = explain_verify_error(hs.verify_error)
            observed["detail"] = hs.verify_error
        return [
            observe(
                host,
                Severity.CRITICAL if hs.verify_error else Severity.PASS,
                "tls",
                observed=observed,
                expected="A certificate from a trusted authority, valid for this name and date",
                context={"problem": str(observed.get("problem", ""))},
            )
        ]
