"""TLS-008 — the certificate uses a strong key (RSA ≥ 2048, EC ≥ 256) and signature."""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_TLS, observe
from corpsec_checks.tls._cert import TlsInfo
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage

_MIN_BITS = {"RSA": 2048, "DSA": 2048, "EC": 256}
_WEAK_HASHES = {"md5", "sha1"}


class CertificateKeyStrength(Check):
    id = "TLS-008"
    version = "1.0.0"
    stage = Stage.ENCRYPTION
    requires: ClassVar[frozenset[str]] = frozenset({FACT_TLS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        info: TlsInfo = ctx.facts.get(FACT_TLS)
        cert = info.cert
        if cert is None:
            return []
        weak_key = cert.key_bits < _MIN_BITS.get(cert.key_type, 0)
        weak_sig = (cert.signature_hash or "").lower() in _WEAK_HASHES
        return [
            observe(
                ctx.target.host,
                Severity.HIGH if weak_key or weak_sig else Severity.PASS,
                "tls",
                observed={
                    "key": f"{cert.key_type} {cert.key_bits}",
                    "signature_hash": cert.signature_hash,
                },
                expected="RSA 2048+ or EC 256+, SHA-256 signature",
            )
        ]
