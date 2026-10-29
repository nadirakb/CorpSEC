import json

import httpx

from corpsec_intel.sync import (
    EOL_URL,
    KEV_URL,
    RDAP_URL,
    RETIRE_URL,
    WORDPRESS_URL,
    build_snapshot,
    parse_retire,
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
