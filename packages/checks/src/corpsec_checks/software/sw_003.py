"""SW-003 — the detected platform/server versions have no known vulnerabilities."""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_FINGERPRINTS, observe
from corpsec_checks.software._fingerprint import Fingerprint
from corpsec_checks.software._vulns import vuln_observation
from corpsec_scanner import Check, Confidence, Observation, ScanContext, Severity, Stage


class KnownVulnerableVersion(Check):
    id = "SW-003"
    version = "1.0.0"
    stage = Stage.SOFTWARE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_FINGERPRINTS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        fps: list[Fingerprint] = ctx.facts.get(FACT_FINGERPRINTS)
        out: list[Observation] = []
        for fp in fps:
            # Spec §6.4: no exact version, no vulnerability finding.
            if not fp.version or fp.product.startswith("wordpress-plugin:"):
                continue
            if fp.product not in ctx.intel.vulns:
                continue
            vulns = ctx.intel.vulns_for(fp.product, fp.version)
            if vulns:
                out.append(
                    vuln_observation(
                        ctx.target.host,
                        ctx.intel,
                        fp.product,
                        fp.version,
                        vulns,
                        confidence=Confidence.LIKELY,
                        source=fp.source,
                    )
                )
            else:
                out.append(
                    observe(
                        ctx.target.host,
                        Severity.PASS,
                        "fingerprint",
                        observed={"product": fp.product, "version": fp.version},
                        dedupe_key=fp.product,
                    )
                )
        return out
