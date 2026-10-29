import json

import httpx
import pytest

from corpsec_intel.sync import (
    EOL_URL,
    KEV_URL,
    RDAP_URL,
    RETIRE_URL,
    WORDFENCE_URL,
    WORDPRESS_URL,
    build_snapshot,
    clean_version,
    parse_retire,
    parse_wordfence,
)
from corpsec_scanner.intel import IntelSnapshot, Product

RETIRE = {
    "jquery": {
        "extractors": {
            "uri": ["/(§§version§§)/jquery(\\.min)?\\.js"],
            "filename": ["jquery-(§§version§§)(\\.min)?\\.js"],
            "filecontent": ["ignored"],
        },
        "vulnerabilities": [
            {
                "below": "3.5.0",
                "atOrAbove": "1.2",
                "severity": "medium",
                "identifiers": {
                    "CVE": ["CVE-2020-11022"],
                    "githubID": "GHSA-gxr4-xjj5-5px2",
                    "summary": "XSS",
                },
            },
            {"below": "1.0", "identifiers": {"summary": "no id"}},
        ],
    },
    "dont check": {"extractors": {"uri": ["x"]}},
}

RESPONSES = {
    WORDPRESS_URL: {"offers": [{"current": "6.8.3"}]},
    EOL_URL.format(product="php"): [
        {"cycle": "8.4", "eol": "2028-12-31", "latest": "8.4.27"},
        {"cycle": "7.4", "eol": "2022-11-28", "latest": "7.4.33"},
    ],
    EOL_URL.format(product="wordpress"): [{"cycle": "6.8", "eol": False, "latest": "6.8.2"}],
    RETIRE_URL: RETIRE,
    KEV_URL: {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]},
    RDAP_URL: {"services": [[["com", "net"], ["http://x/", "https://rdap.verisign.com/com/v1/"]]]},
}


def handler(req: httpx.Request) -> httpx.Response:
    body = RESPONSES.get(str(req.url))
    return httpx.Response(200, json=body) if body is not None else httpx.Response(404)


async def test_build_snapshot() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        snap, failed = await build_snapshot(client)
    assert snap.products["wordpress"].latest == "6.8.3"  # WordPress.org wins over endoflife
    assert snap.products["php"].latest == "8.4.27"
    assert snap.products["php"].is_eol("7.4.33") is True
    assert snap.kev == {"CVE-2021-44228"}
    assert snap.rdap["net"] == "https://rdap.verisign.com/com/v1/"
    [jquery] = snap.js_libraries
    assert jquery.vulns[0].ids == ["CVE-2020-11022", "GHSA-gxr4-xjj5-5px2"]
    assert jquery.vulns[0].affects("1.12.4")
    # the mock has no nginx/apache/drupal/joomla data -> those fail, the rest succeed
    assert sorted(failed) == sorted(
        f"endoflife:{p}" for p in ("nginx", "apache-http-server", "drupal", "joomla")
    )
    # round-trips through JSON
    assert IntelSnapshot.model_validate_json(snap.model_dump_json()).kev == snap.kev


async def test_failed_source_keeps_previous_data() -> None:
    previous = IntelSnapshot(products={"nginx": Product(latest="1.27.0")}, kev={"CVE-1"})

    def kev_down(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503) if str(req.url) == KEV_URL else handler(req)

    async with httpx.AsyncClient(transport=httpx.MockTransport(kev_down)) as client:
        snap, failed = await build_snapshot(client, previous)
    assert "cisa-kev" in failed
    assert snap.kev == {"CVE-1"}
    assert snap.products["nginx"].latest == "1.27.0"


def test_parse_retire_skips_entries_without_ids() -> None:
    [lib] = parse_retire(json.loads(json.dumps(RETIRE)))
    assert len(lib.vulns) == 1


DEFIANT = {
    "notice": "Copyright 2012-2026 Defiant Inc.",
    "license": "Defiant hereby grants you ... include a hyperlink to this vulnerability record",
    "license_url": "https://www.wordfence.com/wti-community-edition-terms-and-conditions/",
}
MITRE = {
    "notice": "Copyright 1999-2026 The MITRE Corporation",
    "license": "CVE Usage: MITRE hereby grants you ...",
    "license_url": "https://www.cve.org/Legal/TermsOfUse",
}


def wf_record(uid: str, **kw: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uid,
        "title": "Contact Form 7 <= 5.3.1 - Unrestricted File Upload",
        "software": [
            {
                "type": "plugin",
                "name": "Contact Form 7",
                "slug": "contact-form-7",
                "affected_versions": {
                    "* - 5.3.1": {
                        "from_version": "*",
                        "from_inclusive": True,
                        "to_version": "5.3.1",
                        "to_inclusive": True,
                    }
                },
                "patched": True,
                "patched_versions": ["5.3.2"],
            }
        ],
        "informational": False,
        "references": ["https://www.wordfence.com/threat-intel/vulnerabilities/id/" + uid],
        "cvss": {"vector": "CVSS:3.1/...", "score": 10.0, "rating": "Critical"},
        "cve": "CVE-2020-35489",
        "copyrights": {"message": "subject to copyright", "defiant": DEFIANT, "mitre": MITRE},
    }
    base.update(kw)
    return base


WF_FEED = {
    "a1": wf_record("a1"),
    "b2": wf_record(
        "b2",
        title="WordPress Core 5.8 - 5.8.2 - SQL Injection",
        software=[
            {
                "type": "core",
                "name": "WordPress",
                "slug": "wordpress",
                "affected_versions": {
                    "(5.8 - 5.8.2]": {
                        "from_version": "5.8",
                        "from_inclusive": False,
                        "to_version": "5.8.3",
                        "to_inclusive": False,
                    }
                },
                "patched": True,
                "patched_versions": ["5.8.3"],
            }
        ],
        cve=None,
        cvss=None,
        copyrights={"message": "x", "defiant": DEFIANT},
    ),
    "c3": wf_record("c3", informational=True),
    "d4": wf_record(
        "d4",
        software=[{"type": "theme", "slug": "astra", "name": "Astra", "affected_versions": {}}],
    ),
}


def test_parse_wordfence() -> None:
    import io

    vulns, attributions = parse_wordfence(io.BytesIO(json.dumps(WF_FEED).encode()))
    assert set(vulns) == {"wordpress-plugin:contact-form-7", "wordpress"}  # theme/info skipped
    [cf7] = vulns["wordpress-plugin:contact-form-7"]
    assert cf7.ids == ["CVE-2020-35489", "WF-a1"]
    assert (cf7.severity, cf7.cvss) == ("critical", 10.0)
    assert cf7.url == "https://www.wordfence.com/threat-intel/vulnerabilities/id/a1"
    assert cf7.copyright == ["defiant", "mitre"]
    assert cf7.affects("5.3.1") and not cf7.affects("5.3.2")
    [core] = vulns["wordpress"]
    assert core.severity is None and core.copyright == ["defiant"]
    assert not core.affects("5.8") and core.affects("5.8.1") and not core.affects("5.8.3")
    assert attributions["mitre"].license_url == "https://www.cve.org/Legal/TermsOfUse"


async def test_wordfence_needs_key_and_replaces_wordpress_data() -> None:
    previous = IntelSnapshot(vulns={"wordpress-plugin:old": [], "drupal": []})
    seen_auth: list[str | None] = []

    def wf(req: httpx.Request) -> httpx.Response:
        if str(req.url) == WORDFENCE_URL:
            seen_auth.append(req.headers.get("authorization"))
            return httpx.Response(200, json=WF_FEED)
        return handler(req)

    async with httpx.AsyncClient(transport=httpx.MockTransport(wf)) as client:
        snap, _ = await build_snapshot(client, previous)
        assert seen_auth == []  # no key: source skipped, previous data kept
        assert "wordpress-plugin:old" in snap.vulns
        snap, failed = await build_snapshot(client, previous, wordfence_key="k3y")
    assert seen_auth == ["Bearer k3y"]
    assert "wordfence" not in failed
    assert "wordpress-plugin:old" not in snap.vulns  # replaced wholesale
    assert "drupal" in snap.vulns  # other products untouched
    assert set(snap.attributions) == {"defiant", "mitre"}


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("5.3.1", "5.3.1"),
        ("44.0 (17-08-2023)", "44.0"),
        ("47.0(20-11-2023)", "47.0"),
        ("v2.1", "2.1"),
        ("4.0.0-beta.1", "4.0.0-beta.1"),
        ("1.0f", "1.0f"),
        (".51.1", None),
        ("latest", None),
    ],
)
def test_clean_version(raw: str, clean: str | None) -> None:
    assert clean_version(raw) == clean


def test_unparseable_bounds_drop_the_range() -> None:
    import io

    bad = wf_record("e5")
    bad["software"][0]["affected_versions"] = {  # type: ignore[index]
        "x": {
            "from_version": "*",
            "from_inclusive": True,
            "to_version": ".51.1",
            "to_inclusive": True,
        },
        "y": {
            "from_version": "1.0",
            "from_inclusive": True,
            "to_version": "44.0 (17-08-2023)",
            "to_inclusive": True,
        },
    }
    vulns, _ = parse_wordfence(io.BytesIO(json.dumps({"e5": bad}).encode()))
    [v] = vulns["wordpress-plugin:contact-form-7"]
    assert len(v.ranges) == 1 and v.ranges[0].last_affected == "44.0"
    assert v.affects("43.9") and not v.affects("44.0.1")


async def test_wordfence_not_refetched_within_interval() -> None:
    from datetime import UTC, datetime, timedelta

    from corpsec_scanner.intel import SourceInfo, Vulnerability

    calls: list[str] = []

    def wf(req: httpx.Request) -> httpx.Response:
        if str(req.url) == WORDFENCE_URL:
            calls.append("wf")
            return httpx.Response(429)
        return handler(req)

    kept = {"wordpress-plugin:x": [Vulnerability(ids=["WF-1"], ranges=[])]}
    recent = IntelSnapshot(
        vulns=kept,
        sources={"wordfence": SourceInfo(url=WORDFENCE_URL, fetched_at=datetime.now(UTC))},
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(wf)) as client:
        snap, failed = await build_snapshot(client, recent, wordfence_key="k")
        assert calls == [] and "wordfence" not in failed
        assert snap.vulns["wordpress-plugin:x"] == kept["wordpress-plugin:x"]

        stale = recent.model_copy(deep=True)
        stale.sources["wordfence"].fetched_at -= timedelta(hours=13)
        snap, failed = await build_snapshot(client, stale, wordfence_key="k")
    assert calls == ["wf"] and "wordfence" in failed  # 429 -> keep previous data
    assert "wordpress-plugin:x" in snap.vulns
