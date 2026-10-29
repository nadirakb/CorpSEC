"""Core data types shared by the scan engine, checks and API (spec §6, §8)."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid() -> str:
    """Return a 26-character Crockford base32 ULID (48-bit ms timestamp + 80 random bits)."""
    value = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def new_id(prefix: str) -> str:
    return f"{prefix}_{new_ulid()}"


def utcnow() -> datetime:
    return datetime.now(UTC)


class Stage(StrEnum):
    """Progress stages shown to the user, in display order."""

    CONNECTION = "connection"
    ENCRYPTION = "encryption"
    WEBSITE = "website"
    SOFTWARE = "software"
    EMAIL = "email"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"  # noqa: S105


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


class FindingStatus(StrEnum):
    OPEN = "open"
    FIXED = "fixed"
    DISMISSED = "dismissed"


class Evidence(BaseModel):
    """What was observed. Every finding must carry evidence (spec §8.3)."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["http", "tls", "dns", "rdap", "fingerprint"]
    captured_at: datetime = Field(default_factory=utcnow)
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    query: str | None = None
    observed: Any = None
    expected: Any = None


class Observation(BaseModel):
    """A raw result emitted by a check. The engine turns observations into findings."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    confidence: Confidence = Confidence.CONFIRMED
    host: str
    evidence: Evidence
    dedupe_key: str = ""
    context: dict[str, str] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Serialized form matches schemas/finding.schema.json."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: new_id("fnd"))
    check_id: str
    check_version: str
    scan_id: str
    site_id: str | None = None
    host: str
    dedupe_key: str = ""
    severity: Severity
    confidence: Confidence
    status: FindingStatus = FindingStatus.OPEN
    dismissed_reason: str | None = None
    evidence: Evidence
    context: dict[str, str] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    fixed_at: datetime | None = None

    @classmethod
    def from_observation(
        cls,
        obs: Observation,
        *,
        check_id: str,
        check_version: str,
        scan_id: str,
        site_id: str | None = None,
    ) -> Finding:
        seen = obs.evidence.captured_at
        return cls(
            check_id=check_id,
            check_version=check_version,
            scan_id=scan_id,
            site_id=site_id,
            host=obs.host,
            dedupe_key=obs.dedupe_key,
            severity=obs.severity,
            confidence=obs.confidence,
            evidence=obs.evidence,
            context=obs.context,
            references=obs.references,
            first_seen=seen,
            last_seen=seen,
        )


class CheckRunStatus(StrEnum):
    OK = "ok"
    SKIPPED = "skipped"
    ERROR = "error"
    TIMEOUT = "timeout"


class CheckRun(BaseModel):
    check_id: str
    check_version: str
    stage: Stage
    status: CheckRunStatus
    duration_ms: int = 0
    detail: str | None = None


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class ScanResult(BaseModel):
    scan_id: str
    target: str
    host: str
    registrable_domain: str
    status: ScanStatus
    started_at: datetime
    finished_at: datetime
    findings: list[Finding] = Field(default_factory=list)
    check_runs: list[CheckRun] = Field(default_factory=list)
    error: str | None = None
