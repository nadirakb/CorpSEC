"""Run a queued scan and persist its result. Shared by the arq worker and tests."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from corpsec_api.db import FindingRow, Scan
from corpsec_api.reporting import apply_grade, grade_findings
from corpsec_scanner import Check, ScanOptions, ScanStatus, run_scan
from corpsec_scanner.models import utcnow
from corpsec_scanner.target import ScanTarget


async def execute_scan(
    sessions: async_sessionmaker[AsyncSession],
    scan_id: str,
    checks: Sequence[Check],
    options: ScanOptions | None = None,
) -> ScanStatus | None:
    async with sessions() as session:
        scan = await session.get(Scan, scan_id, with_for_update=True)
        if scan is None or scan.status != ScanStatus.QUEUED:
            return None
        scan.status = ScanStatus.RUNNING
        scan.started_at = utcnow()
        target = ScanTarget(
            raw=scan.target, host=scan.host, registrable_domain=scan.registrable_domain
        )
        site_id = scan.site_id
        await session.commit()

    result = await run_scan(target, checks, scan_id=scan_id, site_id=site_id, options=options)

    async with sessions() as session:
        scan = await session.get(Scan, scan_id)
        assert scan is not None
        scan.status = result.status
        scan.finished_at = result.finished_at
        scan.error = result.error
        scan.check_runs = [r.model_dump(mode="json") for r in result.check_runs]
        if result.status != ScanStatus.FAILED:
            apply_grade(scan, grade_findings(result.findings, checks))
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
                    first_seen=f.first_seen,
                    last_seen=f.last_seen,
                )
            )
        await session.commit()
    return result.status
