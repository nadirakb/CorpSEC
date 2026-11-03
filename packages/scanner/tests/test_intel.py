from datetime import date

import pytest

from corpsec_scanner.intel import (
    IntelSnapshot,
    Product,
    ReleaseCycle,
    VersionRange,
    Vulnerability,
    compare_versions,
    load_snapshot,
)


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.10", "1.9", 1),
        ("5.0", "5.0.0", 0),
        ("2.0rc1", "2.0", -1),
        ("1.12.4", "3.5.0", -1),
        ("6.4.3", "6.4.10", -1),
        ("3.0.0-beta.1", "3.0.0", -1),
    ],
)
def test_compare_versions(a: str, b: str, expected: int) -> None:
    assert compare_versions(a, b) == expected


def test_range_contains() -> None:
    r = VersionRange(introduced="1.2", fixed="3.5.0")
    assert r.contains("1.12.4")
    assert not r.contains("3.5.0")
    assert not r.contains("1.1")
    assert VersionRange(last_affected="2.0").contains("2.0")


def test_snapshot_lookup_and_kev() -> None:
    v = Vulnerability(ids=["CVE-2020-1"], ranges=[VersionRange(fixed="5.5")])
    snap = IntelSnapshot(vulns={"wordpress": [v]}, kev={"CVE-2020-1"})
    assert snap.vulns_for("wordpress", "5.0") == [v]
    assert snap.vulns_for("wordpress", "6.0") == []
    assert snap.in_kev(v)


def test_eol() -> None:
    php = Product(
        cycles=[
            ReleaseCycle(cycle="7.4", eol=date(2022, 11, 28)),
            ReleaseCycle(cycle="8.3", eol=date(2027, 12, 31)),
        ]
    )
    today = date(2026, 10, 29)
    assert php.is_eol("7.4.33", today) is True
    assert php.is_eol("8.3.1", today) is False
    assert php.is_eol("5.6", today) is None


def test_missing_snapshot_is_empty(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert load_snapshot(tmp_path / "nope.json").empty
