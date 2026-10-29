"""SW-005 — JavaScript libraries loaded by the site have no known vulnerabilities.

Uses retire.js detection patterns (URL and file name) from the intel snapshot.
"""

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import urlsplit

from corpsec_checks._common import FACT_PAGES, observe
from corpsec_checks._html import is_html, parse_html
from corpsec_checks.software._vulns import vuln_observation
from corpsec_scanner import Check, Confidence, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse
from corpsec_scanner.intel import JsLibrary

_VERSION_GROUP = r"([0-9][0-9.a-z_\-]*?)"


def _compile(pattern: str) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern.replace("§§version§§", _VERSION_GROUP))
    except re.error:
        return None


def detect(lib: JsLibrary, url: str) -> str | None:
    filename = urlsplit(url).path.rsplit("/", 1)[-1]
    for pattern, subject in [(p, url) for p in lib.uri_patterns] + [
        (p, filename) for p in lib.filename_patterns
    ]:
        regex = _compile(pattern)
        if regex and (m := regex.search(subject)) and m.groups():
            return m.group(1).rstrip(".-_")
    return None


class VulnerableJsLibraries(Check):
    id = "SW-005"
    version = "1.0.0"
    stage = Stage.SOFTWARE
    requires: ClassVar[frozenset[str]] = frozenset({FACT_PAGES})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        if not ctx.intel.js_libraries:
            return []
        pages: list[HttpResponse] = ctx.facts.get(FACT_PAGES)
        scripts: set[str] = set()
        for p in pages:
            if is_html(p.headers.get("content-type")):
                scripts.update(parse_html(p.text, p.url).script_srcs())
        detected: dict[str, tuple[str, JsLibrary]] = {}
        for url in sorted(scripts):
            for lib in ctx.intel.js_libraries:
                if lib.name not in detected and (version := detect(lib, url)):
                    detected[lib.name] = (version, lib)
        out: list[Observation] = []
        for name, (version, lib) in sorted(detected.items()):
            vulns = [v for v in lib.vulns if v.affects(version)]
            if vulns:
                out.append(
                    vuln_observation(
                        ctx.target.host,
                        ctx.intel,
                        name,
                        version,
                        vulns,
                        confidence=Confidence.LIKELY,
                        source="script URL",
                        severity=Severity.MEDIUM,
                    )
                )
        if not out:
            out.append(
                observe(
                    ctx.target.host,
                    Severity.PASS,
                    "fingerprint",
                    observed={n: v for n, (v, _) in detected.items()},
                )
            )
        return out
