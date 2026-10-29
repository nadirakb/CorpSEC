"""Score, letter, caps and priorities (spec §9)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from corpsec_scanner.models import Confidence, Finding, FindingStatus, Severity, Stage

GRADE_MODEL_VERSION = "1.0.0"
"""Bump when the formula changes, so grade history can mark the change (spec §6.7)."""

WEIGHTS: Mapping[Severity, float] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 15,
    Severity.MEDIUM: 6,
    Severity.LOW: 2,
}
_CONFIDENCE_FACTOR = {Confidence.CONFIRMED: 1.0, Confidence.LIKELY: 0.8}
_LETTERS = ((90, "A"), (80, "B"), (65, "C"), (50, "D"))
_LETTER_ORDER = ["A+", "A", "B", "C", "D", "F"]

# "A+" needs these protections in place on top of a high score (spec §9.2).
A_PLUS_REQUIRES = ("TLS-007", "HDR-001", "MAIL-005|MAIL-007")


@dataclass(frozen=True, slots=True)
class StageGrade:
    score: int
    letter: str
    counted: int
    """Findings that affected this stage's score."""


@dataclass(frozen=True, slots=True)
class GradeReport:
    score: int
    letter: str
    caps: list[str]
    """Why the letter is lower than the score alone would give, e.g. ``["critical"]``."""
    stages: dict[Stage, StageGrade]
    fix_first: list[str]
    """Finding ids, most important first (max 3)."""
    counted: int
    model_version: str = GRADE_MODEL_VERSION
    deductions: dict[str, float] = field(default_factory=dict)
    """Finding id -> points subtracted (after diminishing returns)."""


def letter_for(score: float) -> str:
    for minimum, letter in _LETTERS:
        if score >= minimum:
            return letter
    return "F"


def _cap(letter: str, ceiling: str) -> str:
    return max(letter, ceiling, key=_LETTER_ORDER.index)


def counts(f: Finding, stage_of: Callable[[str], Stage | None]) -> bool:
    """Does this finding affect the grade?"""
    if f.severity not in WEIGHTS or f.confidence not in _CONFIDENCE_FACTOR:
        return False
    if stage_of(f.check_id) is None:  # internal or unknown check
        return False
    if f.status == FindingStatus.FIXED:
        return False
    if f.status == FindingStatus.DISMISSED:
        # A dismissed critical still caps the grade unless it was a false positive (§7.6).
        return f.severity == Severity.CRITICAL and f.dismissed_reason != "false_positive"
    return True


def _score(findings: list[Finding], stage_of: Callable[[str], Stage | None]) -> dict[str, float]:
    """Points per finding. Within a stage, the 3rd and later finding of the same severity
    counts half, so one weak area can't sink the whole score on its own."""
    seen: dict[tuple[Stage | None, Severity], int] = defaultdict(int)
    out: dict[str, float] = {}
    for f in sorted(findings, key=lambda f: (f.check_id, f.host, f.dedupe_key)):
        key = (stage_of(f.check_id), f.severity)
        seen[key] += 1
        weight = WEIGHTS[f.severity]
        out[f.id] = weight if seen[key] <= 2 else weight / 2
    return out


def priority(f: Finding, effort_minutes: int) -> float:
    """Spec §9.3: weight * confidence * effort^-0.3 * (2 if known exploited)."""
    kev = 1.0
    observed = f.evidence.observed
    if isinstance(observed, dict):
        vulns = observed.get("vulnerabilities") or []
        if any(isinstance(v, dict) and v.get("known_exploited") for v in vulns):
            kev = 2.0
    effort_factor: float = 1 / max(effort_minutes, 1) ** 0.3
    return (
        WEIGHTS.get(f.severity, 0) * _CONFIDENCE_FACTOR.get(f.confidence, 0.0) * effort_factor * kev
    )


def grade(
    findings: Iterable[Finding],
    stage_of: Callable[[str], Stage | None],
    *,
    effort_of: Callable[[str], int] = lambda check_id: 30,
    steps_of: Callable[[str], int] = lambda check_id: 3,
) -> GradeReport:
    """Grade a completed scan.

    ``stage_of`` maps check id -> stage (None for internal checks). ``effort_of`` and
    ``steps_of`` come from the explanation templates and only affect ``fix_first``.
    """
    all_findings = list(findings)
    counted = [f for f in all_findings if counts(f, stage_of)]
    points = _score(counted, stage_of)
    score = max(0, round(100 - sum(points.values())))
    letter = letter_for(score)

    caps: list[str] = []
    severities = {f.severity for f in counted}
    if Severity.CRITICAL in severities:
        caps.append("critical")
        letter = "F"
    elif Severity.HIGH in severities:
        caps.append("high")
        letter = _cap(letter, "C")
    if any(f.check_id == "TLS-001" for f in counted) or any(
        f.check_id == "CONN-001" and f.severity == Severity.CRITICAL for f in counted
    ):
        caps.append("no_valid_https")
        letter = "F"

    if letter == "A" and score >= 95 and not (severities - {Severity.LOW}):
        passed = {f.check_id for f in all_findings if f.severity == Severity.PASS}
        if all(any(c in passed for c in alt.split("|")) for alt in A_PLUS_REQUIRES):
            letter = "A+"

    stages: dict[Stage, StageGrade] = {}
    for stage in Stage:
        mine = [f for f in counted if stage_of(f.check_id) == stage]
        stage_points = _score(mine, stage_of)
        s = max(0, round(100 - sum(stage_points.values())))
        stage_letter = letter_for(s)
        sev = {f.severity for f in mine}
        if Severity.CRITICAL in sev:
            stage_letter = "F"
        elif Severity.HIGH in sev:
            stage_letter = _cap(stage_letter, "C")
        stages[stage] = StageGrade(score=s, letter=stage_letter, counted=len(mine))

    open_ = [f for f in counted if f.status == FindingStatus.OPEN]
    ranked = sorted(
        open_,
        key=lambda f: (-priority(f, effort_of(f.check_id)), steps_of(f.check_id), f.check_id),
    )
    fix_first: list[str] = []
    seen_checks: set[str] = set()
    for f in ranked:  # one entry per check: "fix TLS-003" covers both TLS 1.0 and 1.1
        if f.check_id not in seen_checks:
            fix_first.append(f.id)
            seen_checks.add(f.check_id)
        if len(fix_first) == 3:
            break

    return GradeReport(
        score=score,
        letter=letter,
        caps=caps,
        stages=stages,
        fix_first=fix_first,
        counted=len(counted),
        deductions=points,
    )
