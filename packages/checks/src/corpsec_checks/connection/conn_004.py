"""CONN-004 — the HTTPS homepage doesn't load anything over plain HTTP (mixed content)."""

from __future__ import annotations

from typing import ClassVar

from corpsec_checks._common import FACT_HOMEPAGE, observe
from corpsec_checks._html import is_html, parse_html
from corpsec_scanner import Check, Observation, ScanContext, Severity, Stage
from corpsec_scanner.http import HttpResponse

# (tag, attribute) pairs that load a sub-resource or submit data.
_RESOURCE_ATTRS = (
    ("script", "src"),
    ("iframe", "src"),
    ("img", "src"),
    ("audio", "src"),
    ("video", "src"),
    ("source", "src"),
    ("embed", "src"),
    ("object", "data"),
    ("form", "action"),
)


class NoMixedContent(Check):
    id = "CONN-004"
    version = "1.0.0"
    stage = Stage.CONNECTION
    requires: ClassVar[frozenset[str]] = frozenset({FACT_HOMEPAGE})

    async def run(self, ctx: ScanContext) -> list[Observation]:
        page: HttpResponse = ctx.facts.get(FACT_HOMEPAGE)
        if page.scheme != "https" or not is_html(page.headers.get("content-type")):
            return []
        doc = parse_html(page.text, page.url)
        insecure: list[str] = []
        for tag in doc.tags:
            for name, attr in _RESOURCE_ATTRS:
                if tag.name == name and tag.attrs.get(attr, "").lower().startswith("http://"):
                    insecure.append(tag.attrs[attr])
            if (
                tag.name == "link"
                and "stylesheet" in tag.attrs.get("rel", "").lower()
                and tag.attrs.get("href", "").lower().startswith("http://")
            ):
                insecure.append(tag.attrs["href"])
        return [
            observe(
                ctx.target.host,
                Severity.MEDIUM if insecure else Severity.PASS,
                "http",
                observed={"page": page.url, "insecure_resources": insecure[:10]},
                expected="All resources loaded over https://",
            )
        ]
