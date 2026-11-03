"""Shared logic for WordPress add-ons (plugins SW-004, themes SW-009).

The version comes from a file the add-on ships (plugin ``readme.txt`` "Stable tag", theme
``style.css`` "Version") when it is public: likely. Otherwise from ``?ver=`` asset
parameters: possible, because add-ons often reuse the WordPress version there, so such
findings don't affect the grade.
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

MAX_VERSION_FETCHES = 5


class WordPressComponentCheck(Check):
    stage = Stage.SOFTWARE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_FINGERPRINTS, FACT_HOMEPAGE})
    prefix: ClassVar[str]
    """Fingerprint/intel key prefix, e.g. ``wordpress-plugin:``."""
    folder: ClassVar[str]
    """``plugins`` or ``themes`` under ``/wp-content/``."""
    version_file: ClassVar[str]
    version_re: ClassVar[re.Pattern[str]]

    async def run(self, ctx: ScanContext) -> list[Observation]:
        fps: list[Fingerprint] = ctx.facts.get(FACT_FINGERPRINTS)
        found = [f for f in fps if f.product.startswith(self.prefix)]
        if not found:
            return []
        home: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        base = "/".join(home.url.split("/", 3)[:3])

        async def shipped_version(slug: str) -> str | None:
            url = f"{base}/wp-content/{self.folder}/{slug}/{self.version_file}"
            try:
                r = await ctx.http.get(url, verify=False, max_body=8192)
            except httpx.TransportError:
                return None
            if r.status != 200 or r.left_scope:
                return None
            m = self.version_re.search(r.text)
            return m.group(1) if m else None

        slugs = [f.product.split(":", 1)[1] for f in found]
        shipped = await asyncio.gather(*(shipped_version(s) for s in slugs[:MAX_VERSION_FETCHES]))
        out: list[Observation] = []
        for i, fp in enumerate(found):
            from_file = shipped[i] if i < len(shipped) else None
            version = from_file or fp.version
            if not version or fp.product not in ctx.intel.vulns:
                continue
            confidence = Confidence.LIKELY if from_file else Confidence.POSSIBLE
            source = f"{self.version_file}" if from_file else fp.source
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
