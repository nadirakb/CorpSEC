"""Scan engine: orders checks by fact dependencies, runs them concurrently within a time
budget and converts observations into findings."""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field

from corpsec_scanner.check import Check
from corpsec_scanner.context import ScanContext
from corpsec_scanner.dns import DnsClient
from corpsec_scanner.http import HttpPolicy, SafeHttpClient, TransportFactory
from corpsec_scanner.models import (
    CheckRun,
    CheckRunStatus,
    Finding,
    ScanResult,
    ScanStatus,
    Severity,
    Stage,
    new_id,
    utcnow,
)
from corpsec_scanner.netguard import (
    DEFAULT_IP_POLICY,
    BlockedAddressError,
    IpPolicy,
    check_addresses,
    resolve_host,
)
from corpsec_scanner.target import ScanTarget, normalize_target


class PlanError(Exception):
    pass


@dataclass(slots=True)
class ScanOptions:
    budget_seconds: float = 120.0
    per_check_timeout: float = 60.0
    http_policy: HttpPolicy = field(default_factory=HttpPolicy)
    ip_policy: IpPolicy = DEFAULT_IP_POLICY
    transport_factory: TransportFactory | None = None
    dns: DnsClient | None = None
    preflight: bool = True
    """Resolve the target and refuse non-public addresses before running any check."""


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    check_id: str
    stage: Stage
    status: CheckRunStatus
    findings: int
    completed: int
    total: int


ProgressCallback = Callable[[ProgressEvent], Awaitable[None]]

_STAGE_ORDER = {stage: i for i, stage in enumerate(Stage)}
_SEVERITY_ORDER = {sev: i for i, sev in enumerate(Severity)}


def plan(checks: Sequence[Check]) -> list[list[Check]]:
    """Group checks into layers; every check runs after all producers of its required facts."""
    producers: dict[str, list[Check]] = {}
    for check in checks:
        for fact in check.provides:
            producers.setdefault(fact, []).append(check)

    deps: dict[str, set[str]] = {}
    for check in checks:
        deps[check.id] = set()
        for fact in check.requires:
            if fact not in producers:
                raise PlanError(f"{check.id} requires fact {fact!r} that no check provides")
            deps[check.id].update(p.id for p in producers[fact] if p.id != check.id)

    by_id = {c.id: c for c in checks}
    layers: list[list[Check]] = []
    done: set[str] = set()
    while len(done) < len(checks):
        ready = sorted(cid for cid, d in deps.items() if cid not in done and d <= done)
        if not ready:
            pending = sorted(set(deps) - done)
            raise PlanError(f"dependency cycle among {pending}")
        layers.append([by_id[cid] for cid in ready])
        done.update(ready)
    return layers


async def _preflight(target: ScanTarget, policy: IpPolicy) -> str | None:
    """Return a user-facing error, or None if the target may be scanned."""
    try:
        addresses = await resolve_host(target.host)
    except socket.gaierror:
        return f"We couldn't find {target.host}. Check the spelling and try again."
    try:
        check_addresses(target.host, addresses, policy)
    except BlockedAddressError:
        return "CorpSEC can only check public websites."
    return None


async def run_scan(
    target: ScanTarget | str,
    checks: Sequence[Check],
    *,
    scan_id: str | None = None,
    site_id: str | None = None,
    options: ScanOptions | None = None,
    on_progress: ProgressCallback | None = None,
) -> ScanResult:
    opts = options or ScanOptions()
    if isinstance(target, str):
        target = normalize_target(target)
    scan_id = scan_id or new_id("scn")
    started = utcnow()

    def result(status: ScanStatus, **kw: object) -> ScanResult:
        return ScanResult(
            scan_id=scan_id,
            target=target.raw,
            host=target.host,
            registrable_domain=target.registrable_domain,
            status=status,
            started_at=started,
            finished_at=utcnow(),
            **kw,
        )

    layers = plan(checks)

    if opts.preflight:
        error = await _preflight(target, opts.ip_policy)
        if error:
            return result(ScanStatus.FAILED, error=error)

    http = SafeHttpClient(
        target.in_scope,
        opts.http_policy,
        ip_policy=opts.ip_policy,
        transport_factory=opts.transport_factory,
    )
    ctx = ScanContext(scan_id=scan_id, target=target, http=http, dns=opts.dns or DnsClient())
    runs: dict[str, CheckRun] = {}
    findings: list[Finding] = []
    total = len(checks)

    async def run_one(check: Check) -> None:
        t0 = time.monotonic()
        missing = [f for f in check.requires if f not in ctx.facts]
        produced: list[Finding] = []
        detail: str | None = None
        if missing:
            status = CheckRunStatus.SKIPPED
            detail = f"missing facts: {', '.join(sorted(missing))}"
        else:
            try:
                async with asyncio.timeout(opts.per_check_timeout):
                    observations = await check.run(ctx.for_check(check.provides))
                produced = [
                    Finding.from_observation(
                        obs,
                        check_id=check.id,
                        check_version=check.version,
                        scan_id=scan_id,
                        site_id=site_id,
                    )
                    for obs in observations
                ]
                status = CheckRunStatus.OK
            except TimeoutError:
                status = CheckRunStatus.TIMEOUT
            except Exception as exc:
                status = CheckRunStatus.ERROR
                detail = f"{type(exc).__name__}: {exc}"
        findings.extend(produced)
        runs[check.id] = CheckRun(
            check_id=check.id,
            check_version=check.version,
            stage=check.stage,
            status=status,
            duration_ms=int((time.monotonic() - t0) * 1000),
            detail=detail,
        )
        if on_progress:
            await on_progress(
                ProgressEvent(
                    check_id=check.id,
                    stage=check.stage,
                    status=status,
                    findings=len(produced),
                    completed=len(runs),
                    total=total,
                )
            )

    timed_out = False
    try:
        async with asyncio.timeout(opts.budget_seconds):
            for layer in layers:
                await asyncio.gather(*(run_one(c) for c in layer))
    except TimeoutError:
        timed_out = True
    finally:
        await http.aclose()

    if timed_out:
        for check in checks:
            if check.id not in runs:
                runs[check.id] = CheckRun(
                    check_id=check.id,
                    check_version=check.version,
                    stage=check.stage,
                    status=CheckRunStatus.TIMEOUT,
                    detail="scan time budget exhausted",
                )

    ordered_runs = sorted(runs.values(), key=lambda r: (_STAGE_ORDER[r.stage], r.check_id))
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.check_id, f.host, f.dedupe_key))
    failed = any(r.status in (CheckRunStatus.ERROR, CheckRunStatus.TIMEOUT) for r in ordered_runs)
    status = ScanStatus.PARTIAL if failed else ScanStatus.COMPLETED
    return result(status, findings=findings, check_runs=ordered_runs)
