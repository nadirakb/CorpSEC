"""SCR-002 — no scripts from code sites known to have been taken over and turned malicious.

polyfill.io changed hands in 2024 and served malware to the sites that used it; the same
operator ran bootcss, bootcdn and staticfile. Loading from them hands control of the page
to whoever owns the domain now.
"""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_PAGES, observe
from corpsec_checks.website._scripts import third_parties
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage

COMPROMISED = {
    "polyfill.io": "https://sansec.io/research/polyfill-supply-chain-attack",
    "polyfill.com": "https://sansec.io/research/polyfill-supply-chain-attack",
    "bootcss.com": "https://sansec.io/research/polyfill-supply-chain-attack",
    "bootcdn.net": "https://sansec.io/research/polyfill-supply-chain-attack",
    "staticfile.org": "https://sansec.io/research/polyfill-supply-chain-attack",
    "staticfile.net": "https://sansec.io/research/polyfill-supply-chain-attack",
}


def compromised_source(host: str) -> str | None:
    for domain in COMPROMISED:
        if host == domain or host.endswith("." + domain):
            return domain
    return None


class CompromisedScriptSource(Check):
    id = "SCR-002"
    version = "1.0.0"
    stage = Stage.WEBSITE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_PAGES})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        out: list[Observation] = []
        for t in third_parties(ctx, ctx.facts.get(FACT_PAGES) or []):
            source = compromised_source(t.host)
            if source:
                out.append(
                    observe(
                        ctx.target.host,
                        Severity.HIGH,
                        "http",
                        observed={"script": t.url, "source": source, "page": t.page},
                        expected="No files loaded from compromised code sites",
                        dedupe_key=source,
                        references=[COMPROMISED[source]],
                    )
                )
        return out or [observe(ctx.target.host, Severity.PASS, "http")]
