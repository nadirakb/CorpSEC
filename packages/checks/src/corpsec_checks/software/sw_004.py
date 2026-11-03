"""SW-004 — WordPress plugins seen on the site have no known vulnerabilities.

Plugin versions come from the plugin's ``readme.txt`` "Stable tag" when it is public
(likely), otherwise from ``?ver=`` asset parameters (possible — plugins often reuse the
WordPress version there, so such findings don't affect the grade).
"""

from __future__ import annotations

import asyncio
import re
from typing import ClassVar

import httpx

from corpsec_checks._common import FACT_FINGERPRINTS, FACT_HOMEPAGE, observe
from corpsec_checks.software._fingerprint import Fingerprint
from corpsec_checks.software._vulns import vuln_observation
from corpsec_scanner import Check, Confidence, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse

MAX_README_FETCHES = 5
_STABLE_TAG_RE = re.compile(r"^\s*Stable tag:\s*([\d.]+)\s*$", re.I | re.M)


class VulnerablePlugins(Check):
    id = "SW-004"
    version = "1.0.0"
    stage = Stage.SOFTWARE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_FINGERPRINTS, FACT_HOMEPAGE})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        fps: list[Fingerprint] = ctx.facts.get(FACT_FINGERPRINTS)
        plugins = [f for f in fps if f.product.startswith("wordpress-plugin:")]
        if not plugins:
            return []
        home: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        base = "/".join(home.url.split("/", 3)[:3])

        async def readme_version(slug: str) -> str | None:
            try:
                r = await ctx.http.get(
                    f"{base}/wp-content/plugins/{slug}/readme.txt", verify=False, max_body=8192
                )
            except httpx.TransportError:
                return None
            if r.status != 200 or r.left_scope:
                return None
            m = _STABLE_TAG_RE.search(r.text)
            return m.group(1) if m else None

        slugs = [p.product.split(":", 1)[1] for p in plugins]
        readme_versions = await asyncio.gather(
            *(readme_version(s) for s in slugs[:MAX_README_FETCHES])
        )
        out: list[Observation] = []
        for i, fp in enumerate(plugins):
            readme = readme_versions[i] if i < len(readme_versions) else None
            version = readme or fp.version
            if not version or fp.product not in ctx.intel.vulns:
                continue
            confidence = Confidence.LIKELY if readme else Confidence.POSSIBLE
            source = "plugin readme.txt" if readme else fp.source
            vulns = ctx.intel.vulns_for(fp.product, version)
            if vulns:
                out.append(
                    vuln_observation(
                        ctx.target.host,
                        ctx.intel,
                        fp.product,
                        version,
                        vulns,
                        confidence=confidence,
                        source=source,
                    )
                )
            else:
                out.append(
                    observe(
                        ctx.target.host,
                        Severity.PASS,
                        "fingerprint",
                        confidence=confidence,
                        observed={"product": fp.product, "version": version},
                        dedupe_key=fp.product,
                    )
                )
        return out
