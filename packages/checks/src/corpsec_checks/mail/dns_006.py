"""DNS-006 — registered look-alike domains (typosquats) that could be used for phishing.

Informational: someone else's registration isn't a flaw in your setup, so it never lowers the
grade. Look-alikes using the same name servers as your domain are marked as probably yours.
"""

from __future__ import annotations

import asyncio
import re
import secrets
from dataclasses import dataclass

from corpsec_checks._common import observe
from corpsec_scanner import Check, Confidence, Observation, ScanContext, Severity, Stage
from corpsec_scanner.dns import DnsError

MAX_CANDIDATES = 60
MAX_REPORTED = 15
CONCURRENCY = 10
OTHER_TLDS = ("com", "net", "org", "co", "info", "biz", "online", "shop")
SUFFIXES = ("-login", "-secure", "-support", "-online")
HOMOGLYPHS = {"o": "0", "0": "o", "l": "1", "1": "l", "i": "l", "rn": "m", "m": "rn",
              "w": "vv", "vv": "w", "e": "3"}  # fmt: skip
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def lookalikes(domain: str) -> list[str]:
    """Typo, character-swap and other-ending variants, most convincing first."""
    label, _, suffix = domain.partition(".")
    first: list[str] = []  # other endings and look-alike letters fool people the most
    rest: list[str] = []
    for tld in OTHER_TLDS:
        if tld != suffix:
            first.append(f"{label}.{tld}")
    for old, new in HOMOGLYPHS.items():
        start = label.find(old)
        while start != -1:
            first.append(label[:start] + new + label[start + len(old) :] + "." + suffix)
            start = label.find(old, start + 1)
    for i in range(len(label)):
        rest.append(label[:i] + label[i + 1 :] + "." + suffix)  # missing letter
        rest.append(label[:i] + label[i] + label[i:] + "." + suffix)  # doubled letter
        if i < len(label) - 1 and label[i] != label[i + 1]:
            swapped = label[:i] + label[i + 1] + label[i] + label[i + 2 :]
            rest.append(swapped + "." + suffix)  # swapped letters
    rest += [f"{label}{s}.{suffix}" for s in SUFFIXES]
    out: list[str] = []
    for name in first + rest:
        lbl = name.partition(".")[0]
        if name != domain and _LABEL_RE.match(lbl) and name not in out:
            out.append(name)
    return out[:MAX_CANDIDATES]


@dataclass(frozen=True, slots=True)
class Lookalike:
    domain: str
    mail: bool
    website: bool
    probably_yours: bool


class LookalikeDomains(Check):
    id = "DNS-006"
    version = "1.0.0"
    stage = Stage.EMAIL

    async def run(self, ctx: ScanContext) -> list[Observation]:
        domain = ctx.target.registrable_domain
        candidates = lookalikes(domain)
        sem = asyncio.Semaphore(CONCURRENCY)
        try:
            own_ns = {n.lower() for n in await ctx.dns.resolve(domain, "NS")}
        except DnsError:
            own_ns = set()

        # Some endings answer for every name; nothing under them can be judged.
        async def wildcard(suffix: str) -> bool:
            try:
                probe = await ctx.dns.lookup(f"corpsec-{secrets.token_hex(6)}.{suffix}", "A")
                return not probe.nxdomain
            except DnsError:
                return True

        suffixes = sorted({c.partition(".")[2] for c in candidates})
        wild = await asyncio.gather(*map(wildcard, suffixes))
        skip = {s for s, w in zip(suffixes, wild, strict=True) if w}

        async def inspect(name: str) -> Lookalike | None:
            if name.partition(".")[2] in skip:
                return None
            async with sem:
                try:
                    answer = await ctx.dns.lookup(name, "NS")
                    if answer.nxdomain:
                        return None
                    mail = bool(await ctx.dns.resolve(name, "MX"))
                    web = bool(await ctx.dns.resolve(name, "A"))
                except DnsError:
                    return None
            if not (answer.records or mail or web):
                return None
            ns = {n.lower() for n in answer.records}
            return Lookalike(name, mail, web, bool(own_ns and ns and ns <= own_ns))

        found = [x for x in await asyncio.gather(*map(inspect, candidates)) if x]
        others = [x for x in found if not x.probably_yours]
        observed = {
            "checked": len(candidates),
            "lookalikes": [
                {"domain": x.domain, "receives_email": x.mail, "has_website": x.website}
                for x in others[:MAX_REPORTED]
            ],
            "probably_yours": [x.domain for x in found if x.probably_yours][:MAX_REPORTED],
        }
        if not others:
            return [observe(domain, Severity.PASS, "dns", observed=observed)]
        return [
            observe(
                domain,
                Severity.INFO,
                "dns",
                confidence=Confidence.POSSIBLE,
                observed={**observed, "count": len(others), "example": others[0].domain},
                expected="No look-alike domains, or look-alikes registered by you",
            )
        ]
