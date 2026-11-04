"""Run scans and re-checks and persist their results. Shared by the arq worker and tests."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api import events
from corpsec_api.db import FindingCheck, FindingRow, Scan, Site
from corpsec_api.reporting import apply_grade, grade_findings, row_to_finding
from corpsec_scanner import Check, ScanOptions, ScanResult, ScanStatus, Severity, run_scan
from corpsec_scanner.engine import ProgressCallback
from corpsec_scanner.models import CheckRunStatus, FindingStatus, new_id, utcnow
from corpsec_scanner.target import ScanTarget

RecheckResult = Literal["fixed", "still_present", "inconclusive"]


def new_scan(target: ScanTarget, raw: str, *, site_id: str | None, ip: str | None) -> Scan:
    return Scan(
        id=new_id("scn"),
        site_id=site_id,
        target=raw.strip(),
        host=target.host,
        registrable_domain=target.registrable_domain,
        status=ScanStatus.QUEUED,
        requested_by_ip=ip,
    )


def _target(scan: Scan) -> ScanTarget:
    return ScanTarget(raw=scan.target, host=scan.host, registrable_domain=scan.registrable_domain)


async def execute_scan(
    sessions: async_sessionmaker[AsyncSession],
    scan_id: str,
    checks: Sequence[Check],
    options: ScanOptions | None = None,
    on_progress: ProgressCallback | None = None,
) -> ScanStatus | None:
    async with sessions() as session:
        scan = await session.get(Scan, scan_id, with_for_update=True)
        if scan is None or scan.status != ScanStatus.QUEUED:
            return None
        scan.status = ScanStatus.RUNNING
        scan.started_at = utcnow()
        target = _target(scan)
        site_id = scan.site_id
        await session.commit()

    result = await run_scan(
        target, checks, scan_id=scan_id, site_id=site_id, options=options, on_progress=on_progress
    )

    async with sessions() as session:
        scan = await session.get(Scan, scan_id)
        assert scan is not None
        scan.status = result.status
        scan.finished_at = result.finished_at
        scan.error = result.error
        scan.check_runs = [r.model_dump(mode="json") for r in result.check_runs]
        if result.status != ScanStatus.FAILED:
            apply_grade(scan, grade_findings(result.findings, checks))
        first_seen = await _first_seen(session, site_id) if site_id else {}
        for f in result.findings:
            data = f.model_dump(mode="json")
            session.add(
                FindingRow(
                    id=f.id,
                    scan_id=scan_id,
                    site_id=f.site_id,
                    check_id=f.check_id,
                    check_version=f.check_version,
                    host=f.host,
                    dedupe_key=f.dedupe_key,
                    severity=f.severity,
                    confidence=f.confidence,
                    status=f.status,
                    evidence=data["evidence"],
                    context=f.context,
                    references=f.references,
                    first_seen=first_seen.get((f.check_id, f.host, f.dedupe_key), f.first_seen),
                    last_seen=f.last_seen,
                )
            )
        await _record_finished(session, scan, result)
        await session.commit()
    return result.status


PROBLEMS = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


async def _record_finished(session: AsyncSession, scan: Scan, result: ScanResult) -> None:
    """Analytics: the scan's outcome, and problems that went away since the site's last scan."""
    owner = None
    if scan.site_id:
        site = await session.get(Site, scan.site_id)
        owner = site.owner_id if site else None
    problems = [f for f in result.findings if f.severity in PROBLEMS]
    ok_checks = {r.check_id for r in result.check_runs if r.status == CheckRunStatus.OK}
    duration = (
        (result.finished_at - scan.started_at).total_seconds()
        if result.finished_at and scan.started_at
        else None
    )
    events.record(
        session,
        events.SCAN_FINISHED,
        user_id=owner,
        kind="site" if scan.site_id else "anonymous",
        status=str(result.status),
        grade=scan.grade,
        duration_s=round(duration, 1) if duration is not None else None,
        problems=len(problems),
        problem_checks=sorted({f.check_id for f in problems}),
        failed_checks=sorted(
            r.check_id for r in result.check_runs if r.status != CheckRunStatus.OK
        ),
    )
    if not scan.site_id or result.status == ScanStatus.FAILED:
        return
    previous = await session.scalar(
        select(Scan)
        .where(
            Scan.site_id == scan.site_id,
            Scan.id != scan.id,
            Scan.status.in_((ScanStatus.COMPLETED, ScanStatus.PARTIAL)),
        )
        .order_by(Scan.finished_at.desc())
        .limit(1)
    )
    if previous is None:
        return
    before = (
        await session.scalars(
            select(FindingRow).where(
                FindingRow.scan_id == previous.id,
                FindingRow.severity.in_(PROBLEMS),
                FindingRow.status == FindingStatus.OPEN,
            )
        )
    ).all()
    current = {(f.check_id, f.host, f.dedupe_key) for f in problems}
    for row in before:
        # only count it fixed if the check actually ran this time
        if row.check_id in ok_checks and (row.check_id, row.host, row.dedupe_key) not in current:
            events.record(
                session, events.FINDING_FIXED, user_id=owner, check_id=row.check_id, via="rescan"
            )


async def _first_seen(session: AsyncSession, site_id: str) -> dict[tuple[str, str, str], Any]:
    """When each problem was first seen on this site, so history survives re-scans (§8.1)."""
    rows = await session.execute(
        select(
            FindingRow.check_id,
            FindingRow.host,
            FindingRow.dedupe_key,
            func.min(FindingRow.first_seen),
        )
        .where(FindingRow.site_id == site_id)
        .group_by(FindingRow.check_id, FindingRow.host, FindingRow.dedupe_key)
    )
    return {(c, h, k): seen for c, h, k, seen in rows}


def with_dependencies(check_id: str, checks: Sequence[Check]) -> list[Check]:
    """The check plus every check that produces facts it requires or uses."""
    by_fact: dict[str, list[Check]] = {}
    for c in checks:
        for fact in c.provides:
            by_fact.setdefault(fact, []).append(c)
    by_id = {c.id: c for c in checks}
    selected: dict[str, Check] = {}
    stack = [by_id[check_id]]
    while stack:
        c = stack.pop()
        if c.id in selected:
            continue
        selected[c.id] = c
        for fact in c.requires | c.uses:
            stack.extend(by_fact.get(fact, []))
    return list(selected.values())


async def regrade(session: AsyncSession, scan: Scan, checks: Sequence[Check]) -> None:
    rows = (await session.scalars(select(FindingRow).where(FindingRow.scan_id == scan.id))).all()
    apply_grade(scan, grade_findings([row_to_finding(r) for r in rows], checks))


async def execute_recheck(
    sessions: async_sessionmaker[AsyncSession],
    finding_id: str,
    checks: Sequence[Check],
    options: ScanOptions | None = None,
) -> dict[str, Any] | None:
    """Re-run one finding's check (and the checks it depends on) against the live site."""
    async with sessions() as session:
        row = await session.get(FindingRow, finding_id)
        if row is None:
            return None
        scan = await session.get(Scan, row.scan_id)
        assert scan is not None
        target = _target(scan)
        check_id, host, key = row.check_id, row.host, row.dedupe_key

    if check_id not in {c.id for c in checks}:
        return {"result": "inconclusive", "detail": "check no longer exists"}
    result = await run_scan(target, with_dependencies(check_id, checks), options=options)
    run = next((r for r in result.check_runs if r.check_id == check_id), None)
    same = [
        f
        for f in result.findings
        if f.check_id == check_id and f.host == host and f.dedupe_key == key
    ]
    still = [f for f in same if f.severity not in (Severity.PASS, Severity.INFO)]

    outcome: RecheckResult
    if result.status == ScanStatus.FAILED or run is None or run.status != CheckRunStatus.OK:
        outcome = "inconclusive"
    elif still:
        outcome = "still_present"
    else:
        outcome = "fixed"

    async with sessions() as session:
        row = await session.get(FindingRow, finding_id)
        scan = await session.get(Scan, row.scan_id) if row else None
        assert row is not None and scan is not None
        now = utcnow()
        if outcome == "fixed":
            row.status = FindingStatus.FIXED
            row.fixed_at = now
            site = await session.get(Site, scan.site_id) if scan.site_id else None
            events.record(
                session,
                events.FINDING_FIXED,
                user_id=site.owner_id if site else None,
                check_id=row.check_id,
                via="recheck",
            )
        elif outcome == "still_present":
            row.last_seen = now
            row.evidence = still[0].evidence.model_dump(mode="json")
            if row.status == FindingStatus.FIXED:
                row.status, row.fixed_at = FindingStatus.OPEN, None
        detail = {"error": result.error, "check_run": run.model_dump(mode="json") if run else None}
        session.add(FindingCheck(finding_id=finding_id, result=outcome, detail=detail))
        await regrade(session, scan, checks)
        await session.commit()
        return {"result": outcome, "grade": scan.grade, "score": scan.score}
