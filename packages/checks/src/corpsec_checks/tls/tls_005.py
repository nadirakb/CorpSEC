"""TLS-005 — no weak cipher suites (RC4, 3DES, DES, NULL, EXPORT, anonymous)."""

from __future__ import annotations

import ssl
from typing import ClassVar

from corpsec_checks._common import FACT_TLS, observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.tls import TLS1_2, WEAK_SUITE_CATEGORY, WEAK_SUITES


class NoWeakCiphers(Check):
    id = "TLS-005"
    version = "1.0.0"
    stage = Stage.ENCRYPTION
    requires: ClassVar[frozenset[str]] = frozenset({FACT_TLS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        host = ctx.target.host
        remaining = set(WEAK_SUITES)
        accepted: dict[str, str] = {}
        # Offer every weak suite; whenever the server picks one, drop its category and ask
        # again, so we learn each category at the cost of one connection per finding.
        while remaining:
            suites = tuple(code for cat in sorted(remaining) for code in WEAK_SUITES[cat])
            try:
                r = await ctx.tls.hello(host, TLS1_2, suites)
            except (OSError, ssl.SSLError):
                break
            if not r.accepted or r.cipher not in WEAK_SUITE_CATEGORY:
                break
            category = WEAK_SUITE_CATEGORY[r.cipher]
            accepted[category] = f"0x{r.cipher:04X}"
            remaining.discard(category)
        if not accepted:
            return [observe(host, Severity.PASS, "tls", observed="No weak cipher suites accepted")]
        return [
            observe(
                host,
                Severity.HIGH,
                "tls",
                observed={"category": cat, "cipher_suite": code},
                expected="Only modern AEAD/CBC suites with AES or ChaCha20",
                dedupe_key=cat,
            )
            for cat, code in sorted(accepted.items())
        ]
