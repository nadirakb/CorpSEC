"""Check plugin interface (spec §11.1)."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, ClassVar

from corpsec_scanner.models import Observation, Stage

if TYPE_CHECKING:
    from corpsec_scanner.context import ScanContext

CHECK_ID_RE = re.compile(r"^[A-Z]{2,5}-[0-9]{3}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
ENTRY_POINT_GROUP = "corpsec.checks"


class Check(ABC):
    """Base class for all checks.

    A check talks to the outside world only through ``ctx`` (rate-limited HTTP, DNS) and
    shares data with other checks through facts: it may read facts listed in ``requires``
    and must only write facts listed in ``provides``.
    """

    id: ClassVar[str]
    version: ClassVar[str]
    stage: ClassVar[Stage]
    requires: ClassVar[frozenset[str]] = frozenset()
    provides: ClassVar[frozenset[str]] = frozenset()

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "__abstractmethods__", None):
            return
        if not CHECK_ID_RE.match(getattr(cls, "id", "")):
            raise TypeError(f"{cls.__name__}: invalid check id {getattr(cls, 'id', None)!r}")
        if not VERSION_RE.match(getattr(cls, "version", "")):
            raise TypeError(f"{cls.__name__}: invalid version {getattr(cls, 'version', None)!r}")
        if not isinstance(getattr(cls, "stage", None), Stage):
            raise TypeError(f"{cls.__name__}: stage must be a Stage")

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Observation]: ...


def load_checks() -> list[Check]:
    """Instantiate every check registered under the ``corpsec.checks`` entry-point group.

    Each entry point resolves to an iterable of :class:`Check` subclasses.
    """
    checks: list[Check] = []
    seen: set[str] = set()
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        for cls in ep.load():
            if cls.id in seen:
                raise ValueError(f"duplicate check id {cls.id}")
            seen.add(cls.id)
            checks.append(cls())
    return checks
