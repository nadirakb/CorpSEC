from datetime import UTC, datetime

import pytest

from corpsec_grader import grade, letter_for, priority
from corpsec_scanner.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    Stage,
)

STAGES = {
    "CONN-001": Stage.CONNECTION, "CONN-002": Stage.CONNECTION, "TLS-001": Stage.ENCRYPTION,
    "TLS-003": Stage.ENCRYPTION, "TLS-007": Stage.ENCRYPTION, "HDR-001": Stage.WEBSITE,
    "HDR-002": Stage.WEBSITE, "HDR-003": Stage.WEBSITE, "HDR-004": Stage.WEBSITE,
    "HDR-005": Stage.WEBSITE, "SW-003": Stage.SOFTWARE, "SW-004": Stage.SOFTWARE,
    "EXP-001": Stage.SOFTWARE, "MAIL-004": Stage.EMAIL, "MAIL-005": Stage.EMAIL,
    "MAIL-006": Stage.EMAIL, "MAIL-007": Stage.EMAIL,
}  # fmt: skip
NOW = datetime(2026, 10, 29, tzinfo=UTC)


def stage_of(check_id: str) -> Stage | None:
    return STAGES.get(check_id)


def f(
    check_id: str,
    severity: Severity,
    *,
    confidence: Confidence = Confidence.CONFIRMED,
    key: str = "",
    status: FindingStatus = FindingStatus.OPEN,
    dismissed: str | None = None,
    observed: object = None,
) -> Finding:
    return Finding(
        check_id=check_id, check_version="1.0.0", scan_id="scn_x", host="example.com",
        dedupe_key=key, severity=severity, confidence=confidence, status=status,
        dismissed_reason=dismissed, evidence=Evidence(kind="http", observed=observed),
        first_seen=NOW, last_seen=NOW,
    )  # fmt: skip


A_PLUS_PASSES = [
    f("TLS-007", Severity.PASS),
    f("HDR-001", Severity.PASS),
    f("MAIL-005", Severity.PASS),
]


@pytest.mark.parametrize(
    ("score", "letter"),
    [
        (100, "A"),
        (90, "A"),
        (89, "B"),
        (80, "B"),
        (79, "C"),
        (65, "C"),
        (64, "D"),
        (50, "D"),
        (49, "F"),
        (0, "F"),
    ],
)
def test_letter_bands(score: int, letter: str) -> None:
    assert letter_for(score) == letter


def test_clean_scan_with_protections_is_a_plus() -> None:
    r = grade(A_PLUS_PASSES, stage_of)
    assert (r.score, r.letter, r.caps, r.fix_first) == (100, "A+", [], [])


def test_a_plus_needs_protections() -> None:
    r = grade([f("TLS-007", Severity.PASS)], stage_of)
    assert (r.score, r.letter) == (100, "A")


def test_a_plus_blocked_by_medium() -> None:
    r = grade([*A_PLUS_PASSES, f("HDR-004", Severity.MEDIUM)], stage_of)
    assert (r.score, r.letter) == (94, "A")


def test_low_findings_still_allow_a_plus() -> None:
    r = grade([*A_PLUS_PASSES, f("HDR-003", Severity.LOW), f("HDR-004", Severity.LOW)], stage_of)
    assert (r.score, r.letter) == (96, "A+")


def test_critical_caps_at_f() -> None:
    r = grade([f("EXP-001", Severity.CRITICAL)], stage_of)
    assert (r.score, r.letter, r.caps) == (60, "F", ["critical"])
    assert r.stages[Stage.SOFTWARE].letter == "F"
    assert r.stages[Stage.EMAIL].letter == "A"


def test_high_caps_at_c() -> None:
    r = grade([f("CONN-002", Severity.HIGH)], stage_of)
    assert (r.score, r.letter, r.caps) == (85, "C", ["high"])


def test_invalid_certificate_is_f() -> None:
    r = grade([f("TLS-001", Severity.CRITICAL)], stage_of)
    assert r.letter == "F" and "no_valid_https" in r.caps


def test_diminishing_returns_within_stage() -> None:
    mediums = [f(c, Severity.MEDIUM) for c in ("HDR-001", "HDR-002", "HDR-004", "HDR-005")]
    r = grade(mediums, stage_of)
    assert r.score == 100 - 6 - 6 - 3 - 3
    # same count spread over stages: no discount
    spread = [
        f("HDR-001", Severity.MEDIUM),
        f("HDR-002", Severity.MEDIUM),
        f("MAIL-005", Severity.MEDIUM),
        f("MAIL-006", Severity.MEDIUM),
    ]
    assert grade(spread, stage_of).score == 100 - 24


def test_possible_info_pass_and_internal_dont_count() -> None:
    r = grade(
        [
            f("SW-004", Severity.CRITICAL, confidence=Confidence.POSSIBLE),
            f("MAIL-004", Severity.INFO),
            f("CRAWL-001", Severity.HIGH),  # unknown/internal
            f("HDR-001", Severity.PASS),
        ],
        stage_of,
    )
    assert (r.score, r.letter, r.counted) == (100, "A", 0)


def test_fixed_and_dismissed() -> None:
    fixed = f("CONN-002", Severity.HIGH, status=FindingStatus.FIXED)
    accepted = f(
        "HDR-002", Severity.MEDIUM, status=FindingStatus.DISMISSED, dismissed="accepted_risk"
    )
    assert grade([fixed, accepted], stage_of).score == 100
    # dismissed critical still caps unless it's a false positive
    crit = f(
        "EXP-001", Severity.CRITICAL, status=FindingStatus.DISMISSED, dismissed="accepted_risk"
    )
    assert grade([crit], stage_of).letter == "F"
    fp = f("EXP-001", Severity.CRITICAL, status=FindingStatus.DISMISSED, dismissed="false_positive")
    assert grade([fp], stage_of).letter == "A"


def test_score_never_negative() -> None:
    many = [f("EXP-001", Severity.CRITICAL, key=str(i)) for i in range(10)]
    assert grade(many, stage_of).score == 0


def test_fix_first_order() -> None:
    kev = f(
        "SW-003",
        Severity.HIGH,
        confidence=Confidence.LIKELY,
        observed={"vulnerabilities": [{"known_exploited": True}]},
    )
    findings = [
        f("HDR-003", Severity.LOW),
        f("MAIL-004", Severity.HIGH),
        kev,
        f("TLS-003", Severity.MEDIUM, key="TLSv1.0"),
        f("TLS-003", Severity.MEDIUM, key="TLSv1.1"),
        f("EXP-001", Severity.CRITICAL),
    ]
    effort = {"MAIL-004": 15, "SW-003": 20, "EXP-001": 10, "TLS-003": 30, "HDR-003": 10}
    r = grade(findings, stage_of, effort_of=effort.__getitem__)
    by_id = {x.id: x for x in findings}
    assert [by_id[i].check_id for i in r.fix_first] == ["EXP-001", "SW-003", "MAIL-004"]


def test_priority_formula() -> None:
    x = f("MAIL-004", Severity.HIGH, confidence=Confidence.LIKELY)
    assert priority(x, 1) == pytest.approx(15 * 0.8)
    assert priority(x, 32) == pytest.approx(15 * 0.8 / 2.8284, rel=1e-3)
