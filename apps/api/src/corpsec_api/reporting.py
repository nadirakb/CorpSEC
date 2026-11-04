"""Grade a scan and explain its findings, using the check catalog and templates."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from corpsec_api.db import FindingRow, Scan
from corpsec_api.redaction import redact
from corpsec_checks.explain import Explanation, SiteContext, explain, template_for
from corpsec_grader import GradeReport, grade
from corpsec_scanner import Check
from corpsec_scanner.models import Finding, Severity, Stage

_SEVERITY_ORDER = {s.value: i for i, s in enumerate(Severity)}


def stage_lookup(checks: Sequence[Check]) -> Callable[[str], Stage | None]:
    stages = {c.id: c.stage for c in checks if not c.internal}
    return stages.get


def effort_minutes(check_id: str) -> int:
    t = template_for(check_id)
    return t.effort_minutes if t and t.effort_minutes else 30


def _steps(check_id: str) -> int:
    t = template_for(check_id)
    return t.steps if t and t.steps else 3


def grade_findings(findings: Sequence[Finding], checks: Sequence[Check]) -> GradeReport:
    return grade(findings, stage_lookup(checks), effort_of=effort_minutes, steps_of=_steps)


def apply_grade(scan: Scan, report: GradeReport) -> None:
    scan.score = report.score
    scan.grade = report.letter
    scan.grade_caps = report.caps
    scan.fix_first = report.fix_first
    scan.grade_model_version = report.model_version
    scan.stage_grades = {
        stage.value: {"score": g.score, "letter": g.letter, "counted": g.counted}
        for stage, g in report.stages.items()
    }


def row_to_finding(row: FindingRow) -> Finding:
    return Finding.model_validate(
        {
            "id": row.id,
            "check_id": row.check_id,
            "check_version": row.check_version,
            "scan_id": row.scan_id,
            "site_id": row.site_id,
            "host": row.host,
            "dedupe_key": row.dedupe_key,
            "severity": row.severity,
            "confidence": row.confidence,
            "status": row.status,
            "dismissed_reason": row.dismissed_reason,
            "evidence": row.evidence,
            "context": row.context,
            "references": row.references,
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "fixed_at": row.fixed_at,
        }
    )


def explained_findings(
    scan: Scan, rows: Sequence[FindingRow], lang: str = "en", *, redacted: bool = False
) -> list[tuple[Finding, Explanation | None]]:
    findings = [row_to_finding(r) for r in rows]
    if redacted:
        findings = [redact(f) for f in findings]
    site = SiteContext.from_findings(scan.registrable_domain, scan.host, findings)
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.check_id, f.dedupe_key))
    return [(f, explain(f, site, lang)) for f in findings]


def stage_grades_out(scan: Scan) -> dict[str, Any]:
    return scan.stage_grades or {}
