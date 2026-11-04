"""DNS-005 — sub-addresses from public certificate logs; flags forgotten test sites.

Every HTTPS certificate is published in Certificate Transparency logs, so anyone can list
a domain's sub-addresses. Names like ``dev.`` or ``old.`` that still resolve are often
unmaintained copies of the site. Also feeds DNS-004 (subdomain takeover).
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import ClassVar
from urllib.parse import quote

import httpx

from corpsec_checks._common import FACT_SUBDOMAINS, observe
from corpsec_scanner import Check, Confidence, Observation, ScanContext, Severity, Stage
from corpsec_scanner.dns import DnsError
from corpsec_scanner.http import RequestBudgetExceededError

CT_SEARCH = "https://crt.sh/?q={query}&output=json&exclude=expired"
MAX_BODY = 4_000_000
MAX_NAMES = 200
MAX_RESOLVE = 25
MAX_REPORTED = 10

FORGOTTEN_RE = re.compile(
    r"(?:^|[.-])(dev|develop|development|test|testing|staging|stage|stg|old|beta|demo|backup"
    r"|bak|tmp|temp|preprod|uat|qa|sandbox|legacy)\d*(?:[.-]|$)"
)


def names_from_ct(entries: object, domain: str) -> list[str]:
    """Distinct, non-wildcard names under ``domain`` from crt.sh JSON."""
    names: set[str] = set()
    if not isinstance(entries, list):
        return []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for raw in str(entry.get("name_value", "")).splitlines():
            name = raw.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name != domain and name.endswith("." + domain) and " " not in name:
                names.add(name)
    return sorted(names)


def looks_forgotten(name: str, domain: str) -> bool:
    return bool(FORGOTTEN_RE.search(name.removesuffix("." + domain)))


class CertificateTransparency(Check):
    id = "DNS-005"
    version = "1.0.0"
    stage = Stage.EMAIL
    provides: ClassVar[frozenset[str]] = frozenset({FACT_SUBDOMAINS})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        domain = ctx.target.registrable_domain
        url = CT_SEARCH.format(query=quote(f"%.{domain}"))
        try:
            r = await ctx.external.get(url, max_body=MAX_BODY)
            if r.status != 200 or r.truncated:
                return []
            names = names_from_ct(json.loads(r.text), domain)
        except (httpx.HTTPError, ValueError, RequestBudgetExceededError):
            return []  # the log search is often slow; no data is not a finding
        names = [n for n in names if ctx.target.in_scope(n)][:MAX_NAMES]
        ctx.set_fact(FACT_SUBDOMAINS, names)

        suspects = [n for n in names if looks_forgotten(n, domain)][:MAX_RESOLVE]

        async def alive(name: str) -> bool:
            try:
                return bool(await ctx.dns.resolve(name, "A") or await ctx.dns.resolve(name, "AAAA"))
            except DnsError:
                return False

        checked = await asyncio.gather(*map(alive, suspects))
        live = [n for n, ok in zip(suspects, checked, strict=True) if ok]
        observed = {
            "subdomains_found": len(names),
            "examples": names[:MAX_REPORTED],
            "test_sites": live[:MAX_REPORTED],
        }
        if not live:
            return [observe(domain, Severity.PASS, "http", query=url, observed=observed)]
        return [
            observe(
                domain,
                Severity.LOW,
                "http",
                confidence=Confidence.LIKELY,  # judged by name only
                query=url,
                observed={**observed, "first_test_site": live[0]},
                expected="Old and test copies of the site taken offline",
            )
        ]
