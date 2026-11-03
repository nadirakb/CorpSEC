"""Per-scan state handed to every check."""

from __future__ import annotations

from typing import Any

from corpsec_scanner.dns import DnsClient
from corpsec_scanner.http import SafeHttpClient
from corpsec_scanner.target import ScanTarget


class FactError(Exception):
    pass


class Facts:
    """Shared key/value store. Writes are restricted to the writing check's ``provides``."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def _set(self, key: str, value: Any) -> None:
        self._data[key] = value


class ScanContext:
    def __init__(
        self,
        *,
        scan_id: str,
        target: ScanTarget,
        http: SafeHttpClient,
        dns: DnsClient,
        facts: Facts | None = None,
    ) -> None:
        self.scan_id = scan_id
        self.target = target
        self.http = http
        self.dns = dns
        self.facts = facts or Facts()
        self._writable: frozenset[str] = frozenset()

    def for_check(self, provides: frozenset[str]) -> ScanContext:
        """A view of this context that may only write the given facts."""
        view = ScanContext(
            scan_id=self.scan_id,
            target=self.target,
            http=self.http,
            dns=self.dns,
            facts=self.facts,
        )
        view._writable = provides
        return view

    def set_fact(self, key: str, value: Any) -> None:
        if key not in self._writable:
            raise FactError(f"fact {key!r} is not declared in this check's provides")
        self.facts._set(key, value)
