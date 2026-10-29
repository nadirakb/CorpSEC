"""DNS-001 — the domain registration doesn't expire soon (RDAP)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx

from corpsec_checks._common import observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


def expiry_from_rdap(data: dict[str, object]) -> datetime | None:
    events = data.get("events")
    if not isinstance(events, list):
        return None
    for e in events:
        if isinstance(e, dict) and e.get("eventAction") == "expiration":
            try:
                return datetime.fromisoformat(str(e["eventDate"]).replace("Z", "+00:00"))
            except (KeyError, ValueError):
                return None
    return None


class DomainExpiry(Check):
    id = "DNS-001"
    version = "1.0.0"
    stage = Stage.EMAIL

    async def run(self, ctx: ScanContext) -> list[Observation]:
        domain = ctx.target.registrable_domain
        base = ctx.intel.rdap.get(domain.rsplit(".", 1)[-1])
        if not base:
            return []  # registry has no RDAP service (or no intel snapshot)
        url = f"{base.rstrip('/')}/domain/{domain}"
        try:
            r = await ctx.external.get(url, headers={"Accept": "application/rdap+json"})
            expiry = expiry_from_rdap(json.loads(r.text)) if r.status == 200 else None
        except (httpx.TransportError, ValueError):
            return []
        if expiry is None:
            return []
        days = (expiry - datetime.now(UTC)).days
        if days <= 7:
            severity = Severity.CRITICAL
        elif days <= 30:
            severity = Severity.HIGH
        else:
            severity = Severity.PASS
        return [
            observe(
                domain,
                severity,
                "rdap",
                query=url,
                observed={"expires": expiry.isoformat(), "days_left": days},
                expected="Registration valid for more than 30 days (or auto-renew on)",
                context={"days_left": str(days)},
            )
        ]
