"""CONN-003 — ``example.com`` and ``www.example.com`` both work and end up on the same host."""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

import httpx

from corpsec_checks._common import observe
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage


class ApexAndWwwAgree(Check):
    id = "CONN-003"
    version = "1.0.0"
    stage = Stage.CONNECTION

    async def run(self, ctx: ScanContext) -> list[Observation]:
        apex = ctx.target.registrable_domain
        names = [apex, f"www.{apex}"]

        async def final_host(name: str) -> str | None:
            try:
                resp = await ctx.http.get(f"https://{name}/", verify=False, max_body=0)
            except httpx.TransportError:
                return None
            if resp.left_scope and resp.history:
                return urlsplit(resp.history[-1].location).hostname
            return urlsplit(resp.url).hostname

        finals = await asyncio.gather(*(final_host(n) for n in names))
        observed = {name: final for name, final in zip(names, finals, strict=True)}
        ok = all(finals) and len(set(finals)) == 1
        return [
            observe(
                apex,
                Severity.PASS if ok else Severity.LOW,
                "http",
                observed=observed,
                expected="Both addresses work and lead to the same address",
            )
        ]
