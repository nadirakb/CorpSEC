"""``corpsec-intel-sync --out intel.json``: fetch public data sources into one snapshot.

Sources (all public, fetched with plain HTTPS from fixed URLs):

* WordPress.org version API — latest WordPress release
* endoflife.date — release lines and end-of-life dates (PHP, nginx, Apache, CMSs)
* retire.js repository — JavaScript library detection patterns and vulnerabilities
* CISA KEV — CVEs known to be exploited in the wild
* IANA RDAP bootstrap — which registry answers RDAP queries for each TLD
* Wordfence Intelligence (v3 production feed) — WordPress core and plugin vulnerabilities.
  Free for personal and commercial use but needs an API key from a Wordfence.com account
  (``CORPSEC_WORDFENCE_API_KEY``); without one the source is skipped. Its licence requires
  a link to each record plus the Defiant (and, for CVEs, MITRE) notices wherever the data
  is shown, so records keep ``url`` and ``copyright`` and the notices go into
  ``IntelSnapshot.attributions``.

A source that fails keeps its previous data when ``--previous`` is given, so one outage
doesn't wipe a section of the snapshot.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import sys
import tempfile
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import IO, Any

import httpx
import ijson

from corpsec_scanner.intel import (
    Attribution,
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
WORDFENCE_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
WORDFENCE_KEY_ENV = "CORPSEC_WORDFENCE_API_KEY"
WORDFENCE_MIN_INTERVAL = timedelta(hours=12)
"""The feed is rate-limited (HTTP 429 after a couple of downloads in minutes); a fresher
copy in the previous snapshot is reused instead of downloading again."""

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


_WF_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
_WF_PRODUCT = {"core": "wordpress", "plugin": "wordpress-plugin:", "theme": "wordpress-theme:"}


_VERSION_RE = re.compile(r"^[vV]?(\d+(?:\.\d+)*(?:[-.]?[A-Za-z0-9]+)*)")


def clean_version(raw: object) -> str | None:
    """``"44.0 (17-08-2023)"`` -> ``"44.0"``; ``"v1.2"`` -> ``"1.2"``; junk -> None.

    A few feed records carry dates or notes in version fields. Parsed naively they turn
    into bogus versions (44.0.17.8.2023) and wrong matches.
    """
    m = _VERSION_RE.match(str(raw).strip())
    return m.group(1) if m else None


def _wf_range(spec: dict[str, Any]) -> VersionRange | None:
    """Map a Wordfence interval; None if a bound can't be parsed (no finding beats a wrong one)."""
    low, high = spec.get("from_version", "*"), spec.get("to_version", "*")
    rng = VersionRange()
    if low != "*":
        rng.introduced = clean_version(low)
        if rng.introduced is None:
            return None
        rng.introduced_exclusive = not spec.get("from_inclusive", True)
    if high != "*":
        if (bound := clean_version(high)) is None:
            return None
        if spec.get("to_inclusive", True):
            rng.last_affected = bound
        else:
            rng.fixed = bound
    return rng


def parse_wordfence(
    stream: IO[bytes],
) -> tuple[dict[str, list[Vulnerability]], dict[str, Attribution]]:
    """Stream-parse the v3 production feed (it is >150 MB, so never ``json.load`` it).

    Keeps core, plugin and theme records; informational records (no real-world impact) are
    dropped.
    """
    vulns: dict[str, list[Vulnerability]] = {}
    attributions: dict[str, Attribution] = {}
    for _uuid, rec in ijson.kvitems(stream, "", use_float=True):
        if rec.get("informational"):
            continue
        holders = []
        for holder, c in (rec.get("copyrights") or {}).items():
            if isinstance(c, dict) and {"notice", "license", "license_url"} <= c.keys():
                holders.append(holder)
                attributions.setdefault(
                    holder,
                    Attribution(
                        notice=c["notice"], license=c["license"], license_url=c["license_url"]
                    ),
                )
        cvss = rec.get("cvss") or {}
        ids = [rec["cve"]] if rec.get("cve") else []
        ids.append(f"WF-{rec['id']}")
        refs = rec.get("references") or []
        url = next((r for r in refs if "wordfence.com" in r), refs[0] if refs else None)
        for sw in rec.get("software") or []:
            prefix = _WF_PRODUCT.get(sw.get("type", ""))
            if prefix is None:
                continue
            key = prefix if prefix == "wordpress" else prefix + str(sw.get("slug", ""))
            ranges = [
                rng
                for r in (sw.get("affected_versions") or {}).values()
                if (rng := _wf_range(r)) is not None
            ]
            if not ranges:
                continue
            vulns.setdefault(key, []).append(
                Vulnerability(
                    ids=ids,
                    severity=_WF_SEVERITY.get(str(cvss.get("rating", "")).lower()),
                    cvss=cvss.get("score"),
                    summary=str(rec.get("title", ""))[:300],
                    ranges=ranges,
                    url=url,
                    copyright=holders,
                )
            )
    return vulns, attributions


async def build_snapshot(
    client: httpx.AsyncClient,
    previous: IntelSnapshot | None = None,
    *,
    wordfence_key: str | None = None,
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
        attributions=dict(prev.attributions),
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

    async def wordfence() -> None:
        headers = {"Authorization": f"Bearer {wordfence_key}"}
        with tempfile.TemporaryFile() as f:
            async with client.stream("GET", WORDFENCE_URL, headers=headers, timeout=600) as r:
                if r.status_code == 429:
                    log.warning(
                        "wordfence rate limit hit; Retry-After: %s",
                        r.headers.get("retry-after", "not given"),
                    )
                r.raise_for_status()
                async for chunk in r.aiter_bytes():
                    f.write(chunk)
            f.seek(0)
            vulns, attributions = await asyncio.to_thread(parse_wordfence, f)
        # replace all WordPress data at once, so removed records disappear too
        snap.vulns = {k: v for k, v in snap.vulns.items() if not k.startswith("wordpress")}
        snap.vulns.update(vulns)
        snap.attributions.update(attributions)

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
    wf_prev = prev.sources.get("wordfence")
    wf_fresh = (
        wf_prev is not None
        and datetime.now(UTC) - wf_prev.fetched_at < WORDFENCE_MIN_INTERVAL
        and any(k.startswith("wordpress") for k in prev.vulns)
    )
    if wordfence_key and wf_fresh:
        assert wf_prev is not None
        log.info("wordfence skipped: previous copy is from %s", wf_prev.fetched_at.isoformat())
    elif wordfence_key:
        await source(
            "wordfence",
            WORDFENCE_URL,
            "https://www.wordfence.com/wti-community-edition-terms-and-conditions/",
            wordfence,
        )
    else:
        log.info(
            "wordfence skipped: set %s to include WordPress vulnerabilities", WORDFENCE_KEY_ENV
        )
    return snap, failed


async def sync_file(
    out: Path,
    *,
    previous: Path | None = None,
    wordfence_key: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> list[str]:
    """Build a snapshot and replace ``out`` atomically. Returns the sources that failed.

    Used by the CLI and by the worker's nightly job (``corpsec_api.worker``).
    """
    prev = load_snapshot(previous) if previous else None
    if client is None:
        async with httpx.AsyncClient(
            timeout=60, headers={"User-Agent": USER_AGENT}, follow_redirects=True
        ) as own:
            snap, failed = await build_snapshot(own, prev, wordfence_key=wordfence_key)
    else:
        snap, failed = await build_snapshot(client, prev, wordfence_key=wordfence_key)

    def write() -> None:
        tmp = out.with_suffix(out.suffix + ".tmp")
        tmp.write_text(snap.model_dump_json())
        tmp.replace(out)  # atomic: scans never read a half-written file

    # ~20 MB of JSON: keep the worker's event loop free while it is written
    await asyncio.to_thread(write)
    log.info(
        "wrote %s: %d products, %d JS libraries, %d KEV CVEs, %d RDAP TLDs, "
        "%d WordPress products with vulnerabilities; failed: %s",
        out,
        len(snap.products),
        len(snap.js_libraries),
        len(snap.kev),
        len(snap.rdap),
        sum(k.startswith("wordpress") for k in snap.vulns),
        ", ".join(failed) or "none",
    )
    return failed


async def _run(out: Path, previous: Path | None) -> int:
    failed = await sync_file(
        out, previous=previous, wordfence_key=os.environ.get(WORDFENCE_KEY_ENV) or None
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
