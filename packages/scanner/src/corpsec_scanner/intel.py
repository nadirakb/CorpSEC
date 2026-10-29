"""Vulnerability / product intelligence snapshot (spec §6.4).

The snapshot is a JSON file produced by ``corpsec-intel-sync`` (packages/intel). Scans read
it locally and never call third-party vulnerability APIs inline. Keeping it as a file also
means scan workers need no database credentials (spec §15).
"""

from __future__ import annotations

import re
from datetime import date, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class VersionRange(BaseModel):
    introduced: str | None = None
    """First affected version (inclusive). ``None`` = all earlier versions."""
    fixed: str | None = None
    """First fixed version (exclusive upper bound)."""
    last_affected: str | None = None
    """Inclusive upper bound, when no fixed version exists."""

    def contains(self, version: str) -> bool:
        if self.introduced and compare_versions(version, self.introduced) < 0:
            return False
        if self.fixed and compare_versions(version, self.fixed) >= 0:
            return False
        return not (self.last_affected and compare_versions(version, self.last_affected) > 0)


class Vulnerability(BaseModel):
    ids: list[str]
    severity: Literal["critical", "high", "medium", "low"] | None = None
    cvss: float | None = None
    summary: str = ""
    ranges: list[VersionRange]

    def affects(self, version: str) -> bool:
        return any(r.contains(version) for r in self.ranges)


class ReleaseCycle(BaseModel):
    cycle: str
    eol: date | bool | None = None
    latest: str | None = None


class Product(BaseModel):
    latest: str | None = None
    cycles: list[ReleaseCycle] = Field(default_factory=list)

    def cycle_for(self, version: str) -> ReleaseCycle | None:
        best: ReleaseCycle | None = None
        for c in self.cycles:
            matches = version == c.cycle or version.startswith(c.cycle + ".")
            if matches and (best is None or len(c.cycle) > len(best.cycle)):
                best = c
        return best

    def is_eol(self, version: str, today: date | None = None) -> bool | None:
        cycle = self.cycle_for(version)
        if cycle is None or cycle.eol is None:
            return None
        if isinstance(cycle.eol, bool):
            return cycle.eol
        return cycle.eol <= (today or date.today())


class JsLibrary(BaseModel):
    """Detection patterns use retire.js syntax: ``§§version§§`` marks the version group."""

    name: str
    uri_patterns: list[str] = Field(default_factory=list)
    filename_patterns: list[str] = Field(default_factory=list)
    vulns: list[Vulnerability] = Field(default_factory=list)


class SourceInfo(BaseModel):
    url: str
    fetched_at: datetime
    license: str | None = None


class IntelSnapshot(BaseModel):
    generated_at: datetime | None = None
    sources: dict[str, SourceInfo] = Field(default_factory=dict)
    products: dict[str, Product] = Field(default_factory=dict)
    """Keyed by product id: ``wordpress``, ``joomla``, ``drupal``, ``php``, ..."""
    vulns: dict[str, list[Vulnerability]] = Field(default_factory=dict)
    """Keyed by ``wordpress``, ``wordpress-plugin:<slug>``, ``joomla``, ``drupal``, ..."""
    js_libraries: list[JsLibrary] = Field(default_factory=list)
    kev: set[str] = Field(default_factory=set)
    """CVE ids in the CISA Known Exploited Vulnerabilities catalog."""
    rdap: dict[str, str] = Field(default_factory=dict)
    """TLD -> RDAP base URL (IANA bootstrap)."""

    @property
    def empty(self) -> bool:
        return self.generated_at is None

    def vulns_for(self, key: str, version: str) -> list[Vulnerability]:
        return [v for v in self.vulns.get(key, []) if v.affects(version)]

    def in_kev(self, vuln: Vulnerability) -> bool:
        return any(i in self.kev for i in vuln.ids)


EMPTY_SNAPSHOT = IntelSnapshot()


def load_snapshot(path: str | Path | None) -> IntelSnapshot:
    """Load a snapshot, or return an empty one if the file doesn't exist."""
    if path is None:
        return EMPTY_SNAPSHOT
    p = Path(path)
    if not p.exists():
        return EMPTY_SNAPSHOT
    return IntelSnapshot.model_validate_json(p.read_bytes())


_PART_RE = re.compile(r"(\d+|[a-z]+)")
_PRE_RELEASE = {"dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2, "rc": -1}


def _key(version: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for part in _PART_RE.findall(version.lower()):
        if part.isdigit():
            out.append((1, int(part)))
        else:
            out.append((0, _PRE_RELEASE.get(part, -5)))
    # Trailing zeros don't matter: 5.0 == 5.0.0
    while out and out[-1] == (1, 0):
        out.pop()
    return out


def compare_versions(a: str, b: str) -> int:
    """Loose numeric comparison: ``1.10 > 1.9``, ``5.0 == 5.0.0``, ``2.0rc1 < 2.0``."""
    ka, kb = _key(a), _key(b)
    # Pad with a "release" marker so 2.0 > 2.0rc1 (pre-release sorts below release).
    n = max(len(ka), len(kb))
    ka += [(1, 0)] * (n - len(ka))
    kb += [(1, 0)] * (n - len(kb))
    return (ka > kb) - (ka < kb)
