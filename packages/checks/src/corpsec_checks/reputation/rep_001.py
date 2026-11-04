"""REP-001 — the domain is not on the Spamhaus Domain Block List (spam, phishing, malware)."""

from __future__ import annotations

from corpsec_checks._common import observe
from corpsec_checks.reputation._dnsbl import query, zone
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage

# https://www.spamhaus.org/faqs/domain-blocklist/#291
DBL_CODES = {
    "127.0.1.2": ("spam", Severity.MEDIUM),
    "127.0.1.4": ("phishing", Severity.HIGH),
    "127.0.1.5": ("malware", Severity.HIGH),
    "127.0.1.6": ("botnet control", Severity.HIGH),
    "127.0.1.102": ("spam (hacked site)", Severity.MEDIUM),
    "127.0.1.103": ("spam redirect (hacked site)", Severity.MEDIUM),
    "127.0.1.104": ("phishing (hacked site)", Severity.HIGH),
    "127.0.1.105": ("malware (hacked site)", Severity.HIGH),
    "127.0.1.106": ("botnet control (hacked site)", Severity.HIGH),
}
_ORDER = [Severity.HIGH, Severity.MEDIUM]


class DomainBlocklist(Check):
    id = "REP-001"
    version = "1.0.0"
    stage = Stage.EMAIL

    async def run(self, ctx: ScanContext) -> list[Observation]:
        dbl = zone(ctx.config, "dbl.spamhaus.org", "dbl.dq.spamhaus.net")
        names = sorted({ctx.target.registrable_domain, ctx.target.host})
        out: list[Observation] = []
        clean: list[str] = []
        for name in names:
            listing = await query(ctx.dns, f"{name}.{dbl}")
            if listing is None:
                continue
            if not listing.listed:
                clean.append(name)
                continue
            reasons = [DBL_CODES[c] for c in listing.codes if c in DBL_CODES]
            if not reasons:
                continue  # unknown answer: don't guess
            reason, severity = min(reasons, key=lambda r: _ORDER.index(r[1]))
            out.append(
                observe(
                    name,
                    severity,
                    "dns",
                    query=f"{name}.dbl.spamhaus.org A",
                    observed={
                        "list": "Spamhaus DBL",
                        "reason": reason,
                        "codes": listing.codes,
                    },
                    expected="Not listed",
                    dedupe_key=name,
                    references=[f"https://check.spamhaus.org/results/?query={name}"],
                )
            )
        if out:
            return out
        if clean:
            return [observe(ctx.target.registrable_domain, Severity.PASS, "dns", observed=clean)]
        return []  # the list couldn't be asked (see _dnsbl)
