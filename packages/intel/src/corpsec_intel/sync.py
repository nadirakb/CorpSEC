"""``corpsec-intel-sync --out intel.json``: fetch public data sources into one snapshot.

Sources (all public, fetched with plain HTTPS from fixed URLs):

* WordPress.org version API — latest WordPress release
* endoflife.date — release lines and end-of-life dates (PHP, nginx, Apache, CMSs)
* retire.js repository — JavaScript library detection patterns and vulnerabilities
* CISA KEV — CVEs known to be exploited in the wild
* IANA RDAP bootstrap — which registry answers RDAP queries for each TLD

WordPress core/plugin vulnerability data is not included yet: the data source is an open
decision (spec §17 Q1). The snapshot format already supports it (``vulns`` keyed by
``wordpress`` / ``wordpress-plugin:<slug>``).

A source that fails keeps its previous data when ``--previous`` is given, so one outage
doesn't wipe a section of the snapshot.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from corpsec_scanner.intel import (
    IntelSnapshot,
    JsLibrary,
    Product,
    ReleaseCycle,
    SourceInfo,
    VersionRange,
    Vulnerability,
    compare_versions,
    load_snapshot,
)

log = logging.getLogger("corpsec_intel")

WORDPRESS_URL = "https://api.wordpress.org/core/version-check/1.7/"
EOL_URL = "https://endoflife.date/api/{product}.json"
RETIRE_URL = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RDAP_URL = "https://data.iana.org/rdap/dns.json"

# endoflife.date product id -> CorpSEC fingerprint product id
EOL_PRODUCTS = {
    "php": "php",
    "nginx": "nginx",
    "apache-http-server": "apache-http-server",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
}
USER_AGENT = "CorpSEC-intel/0.1 (+https://corpsec.app/bot)"


async def _json(client: httpx.AsyncClient, url: str) -> Any:
    r = await client.get(url)
    r.raise_for_status()
    return r.json()


def parse_eol(rows: list[dict[str, Any]]) -> Product:
    cycles = []
    for row in rows:
        eol = row.get("eol")
        if isinstance(eol, str):
            eol_value: Any = datetime.fromisoformat(eol).date()
        else:
            eol_value = eol if isinstance(eol, bool) else None
        cycles.append(
            ReleaseCycle(cycle=str(row["cycle"]), eol=eol_value, latest=row.get("latest"))
        )
    latest = None
    for c in cycles:
        if c.latest and (latest is None or compare_versions(c.latest, latest) > 0):
            latest = c.latest
    return Product(latest=latest, cycles=cycles)


def parse_retire(repo: dict[str, Any]) -> list[JsLibrary]:
    libs = []
    for name, entry in sorted(repo.items()):
        if name == "dont check" or not isinstance(entry, dict):
            continue
        extractors = entry.get("extractors", {})
        vulns = []
        for v in entry.get("vulnerabilities", []):
            idents = v.get("identifiers", {})
            ids = list(idents.get("CVE", []))
            if idents.get("githubID"):
                ids.append(idents["githubID"])
            if not ids:
                continue
            severity = v.get("severity")
            vulns.append(
                Vulnerability(
                    ids=ids,
                    severity=severity
                    if severity in ("critical", "high", "medium", "low")
                    else None,
                    summary=str(idents.get("summary", ""))[:300],
                    ranges=[VersionRange(introduced=v.get("atOrAbove"), fixed=v.get("below"))],
                )
            )
        uri = extractors.get("uri", [])
        filename = extractors.get("filename", [])
        if uri or filename:
            libs.append(
                JsLibrary(name=name, uri_patterns=uri, filename_patterns=filename, vulns=vulns)
            )
    return libs


def parse_rdap(data: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for tlds, urls in data.get("services", []):
        https = [u for u in urls if u.startswith("https://")] or urls
        for tld in tlds:
            out[tld.lower()] = https[0]
    return out


async def build_snapshot(
    client: httpx.AsyncClient, previous: IntelSnapshot | None = None
) -> tuple[IntelSnapshot, list[str]]:
    """Return the new snapshot and the names of sources that failed."""
    prev = previous or IntelSnapshot()
    snap = IntelSnapshot(
        generated_at=datetime.now(UTC),
        products=dict(prev.products),
        vulns=dict(prev.vulns),
        js_libraries=list(prev.js_libraries),
        kev=set(prev.kev),
        rdap=dict(prev.rdap),
        sources=dict(prev.sources),
    )
    failed: list[str] = []

    async def source(
        name: str, url: str, license_: str | None, apply: Callable[[], Awaitable[None]]
    ) -> None:
        try:
            await apply()
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            log.warning("source %s failed: %s", name, exc)
            failed.append(name)
            return
        snap.sources[name] = SourceInfo(url=url, fetched_at=datetime.now(UTC), license=license_)

    async def eol(product: str) -> None:
        rows = await _json(client, EOL_URL.format(product=product))
        snap.products[EOL_PRODUCTS[product]] = parse_eol(rows)

    async def wordpress() -> None:
        data = await _json(client, WORDPRESS_URL)
        wp = snap.products.get("wordpress", Product())
        snap.products["wordpress"] = wp.model_copy(update={"latest": data["offers"][0]["current"]})

    async def retire() -> None:
        snap.js_libraries = parse_retire(await _json(client, RETIRE_URL))

    async def kev() -> None:
        data = await _json(client, KEV_URL)
        snap.kev = {v["cveID"] for v in data["vulnerabilities"]}

    async def rdap() -> None:
        snap.rdap = parse_rdap(await _json(client, RDAP_URL))

    # endoflife first so the WordPress.org "latest" overrides endoflife's value
    await asyncio.gather(
        *(
            source(f"endoflife:{p}", EOL_URL.format(product=p), "MIT", lambda p=p: eol(p))  # type: ignore[misc]
            for p in EOL_PRODUCTS
        )
    )
    await asyncio.gather(
        source("wordpress.org", WORDPRESS_URL, None, wordpress),
        source("retire.js", RETIRE_URL, "Apache-2.0", retire),
        source("cisa-kev", KEV_URL, "CC0-1.0", kev),
        source("iana-rdap", RDAP_URL, None, rdap),
    )
    return snap, failed


async def _run(out: Path, previous: Path | None) -> int:
    prev = load_snapshot(previous) if previous else None
    async with httpx.AsyncClient(
        timeout=60, headers={"User-Agent": USER_AGENT}, follow_redirects=True
    ) as client:
        snap, failed = await build_snapshot(client, prev)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(snap.model_dump_json())
    tmp.replace(out)  # atomic: scans never read a half-written file
    log.info(
        "wrote %s: %d products, %d JS libraries, %d KEV CVEs, %d RDAP TLDs; failed: %s",
        out,
        len(snap.products),
        len(snap.js_libraries),
        len(snap.kev),
        len(snap.rdap),
        ", ".join(failed) or "none",
    )
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="corpsec-intel-sync", description=__doc__.split("\n")[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--previous", type=Path, help="existing snapshot to keep data from for failed sources"
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    return asyncio.run(_run(args.out, args.previous))


if __name__ == "__main__":
    raise SystemExit(main())
