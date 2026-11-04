"""DNS-004 — no subdomain points at a deleted cloud resource (subdomain takeover).

Subdomains come from the certificate's names and public certificate logs (DNS-005), never
brute force. A finding needs either a
service-specific "this doesn't exist" page, or NXDOMAIN for a service where a missing
name can be re-registered by anyone.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import ClassVar

import httpx

from corpsec_checks._common import FACT_SUBDOMAINS, FACT_TLS, observe
from corpsec_checks.tls._cert import TlsInfo
from corpsec_scanner import Check, Confidence, Observation, ScanContext, Severity, Stage
from corpsec_scanner.dns import DnsError

MAX_SUBDOMAINS = 10


@dataclass(frozen=True, slots=True)
class Service:
    name: str
    cname_suffixes: tuple[str, ...]
    body_fingerprint: str | None = None
    nxdomain_vulnerable: bool = False


SERVICES = (
    Service("Amazon S3", (".s3.amazonaws.com", ".s3-website", ".s3.dualstack"), "NoSuchBucket"),
    Service("GitHub Pages", (".github.io",), "There isn't a GitHub Pages site here."),
    Service("Heroku", (".herokuapp.com", ".herokudns.com"), "No such app"),
    Service("Shopify", (".myshopify.com",), "Sorry, this shop is currently unavailable."),
    Service("Fastly", (".fastly.net",), "Fastly error: unknown domain"),
    Service("Pantheon", (".pantheonsite.io",), "The gods are wise"),
    Service(
        "Microsoft Azure",
        (
            ".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net",
            ".blob.core.windows.net", ".azureedge.net", ".azure-api.net",
        ),
        nxdomain_vulnerable=True,
    ),
    Service("AWS Elastic Beanstalk", (".elasticbeanstalk.com",), nxdomain_vulnerable=True),
)  # fmt: skip


def match_service(cname: str) -> Service | None:
    for s in SERVICES:
        if any(suffix in cname for suffix in s.cname_suffixes):
            return s
    return None


class SubdomainTakeover(Check):
    id = "DNS-004"
    version = "1.1.0"
    stage = Stage.EMAIL
    uses: ClassVar[frozenset[str]] = frozenset({FACT_TLS, FACT_SUBDOMAINS})

    def candidates(self, ctx: ScanContext) -> list[str]:
        domain = ctx.target.registrable_domain
        names = {f"www.{domain}", ctx.target.host}
        info: TlsInfo | None = ctx.facts.get(FACT_TLS)
        if info and info.cert:
            names.update(n.lower() for n in info.cert.sans if not n.startswith("*."))
        names.update(ctx.facts.get(FACT_SUBDOMAINS) or [])
        names.discard(domain)
        return sorted(n for n in names if ctx.target.in_scope(n))[:MAX_SUBDOMAINS]

    async def run(self, ctx: ScanContext) -> list[Observation]:
        names = self.candidates(ctx)

        async def inspect(name: str) -> Observation | None:
            try:
                cnames = await ctx.dns.resolve(name, "CNAME")
            except DnsError:
                return None
            if not cnames:
                return None
            target = cnames[0].rstrip(".").lower()
            service = match_service(target)
            if service is None:
                return None
            evidence: dict[str, object] = {
                "subdomain": name,
                "cname": target,
                "service": service.name,
            }
            confidence: Confidence | None = None
            if service.nxdomain_vulnerable:
                try:
                    if (await ctx.dns.lookup(target, "A")).nxdomain:
                        evidence["target"] = "does not exist (NXDOMAIN)"
                        confidence = Confidence.LIKELY
                except DnsError:
                    pass
            if service.body_fingerprint and confidence is None:
                try:
                    r = await ctx.http.get(f"http://{name}/", verify=False, max_body=16_384)
                    if service.body_fingerprint in r.text:
                        evidence["page"] = service.body_fingerprint
                        confidence = Confidence.CONFIRMED
                except httpx.TransportError:
                    pass
            if confidence is None:
                return None
            return observe(
                name,
                Severity.HIGH,
                "dns",
                confidence=confidence,
                query=f"{name} CNAME",
                observed=evidence,
                expected="DNS records removed when a service is deleted",
                dedupe_key=name,
            )

        results = [r for r in await asyncio.gather(*map(inspect, names)) if r]
        return results or [
            observe(ctx.target.registrable_domain, Severity.PASS, "dns", observed=names)
        ]
