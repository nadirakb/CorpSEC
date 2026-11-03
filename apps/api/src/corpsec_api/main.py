"""CorpSEC HTTP API (spec §13). Run: ``uvicorn corpsec_api.main:app``.

No ``from __future__ import annotations`` here: FastAPI must resolve the dependency
aliases defined inside ``create_app`` at runtime.
"""

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any, Literal

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api.db import AuditLog, FindingRow, Scan, make_engine
from corpsec_api.progress import Event, ProgressBus, RedisProgressBus
from corpsec_api.queue import ArqScanQueue, ScanQueue
from corpsec_api.reporting import explained_findings
from corpsec_api.scans import regrade
from corpsec_api.settings import get_settings
from corpsec_checks.explain import Explanation, load_templates
from corpsec_scanner import InvalidTargetError, ScanStatus, Severity, load_checks, normalize_target
from corpsec_scanner.models import FindingStatus, new_id


class ScanCreate(BaseModel):
    target: str = Field(max_length=2048, examples=["example.com"])


class ScanCreated(BaseModel):
    id: str
    status: str


class FindingOut(BaseModel):
    id: str
    check_id: str
    check_version: str
    host: str
    dedupe_key: str
    severity: str
    confidence: str
    status: str
    evidence: dict[str, Any]
    context: dict[str, Any]
    references: list[str]
    first_seen: datetime
    fixed_at: datetime | None
    dismissed_reason: str | None
    explanation: Explanation | None


class StageGradeOut(BaseModel):
    score: int
    letter: str
    counted: int


class ScanOut(BaseModel):
    id: str
    target: str
    host: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    score: int | None
    grade: str | None
    grade_caps: list[str]
    stage_grades: dict[str, StageGradeOut]
    fix_first: list[str]
    """Finding ids, most important first."""
    error: str | None
    check_runs: list[dict[str, Any]]
    findings: list[FindingOut]
    """Sorted by severity (critical first; passes last)."""


class DismissIn(BaseModel):
    reason: Literal["accepted_risk", "false_positive", "not_applicable"]


class RecheckOut(BaseModel):
    result: Literal["fixed", "still_present", "inconclusive"]
    grade: str | None = None
    score: int | None = None


FINISHED = {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED}
HEARTBEAT_SECONDS = 15.0


def sse(event: Event) -> str:
    return f"event: {event.get('type', 'message')}\ndata: {json.dumps(event)}\n\n"


def problem(status: int, title: str, detail: str | None = None) -> JSONResponse:
    """RFC 9457 problem details. ``title`` is user-facing."""
    body: dict[str, Any] = {"type": "about:blank", "title": title, "status": status}
    if detail:
        body["detail"] = detail
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


def create_app(
    *,
    sessions: async_sessionmaker[AsyncSession] | None = None,
    queue: ScanQueue | None = None,
    progress: ProgressBus | None = None,
) -> FastAPI:
    """Build the app. Tests inject ``sessions`` and ``queue``; otherwise they come from settings."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        cleanup: list[Callable[[], Awaitable[Any]]] = []
        settings = get_settings()
        if app.state.sessions is None:
            engine = make_engine(settings.database_url)
            app.state.sessions = async_sessionmaker(engine, expire_on_commit=False)
            cleanup.append(engine.dispose)
        if app.state.queue is None:
            redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
            app.state.queue = ArqScanQueue(redis)
            if app.state.progress is None:
                app.state.progress = RedisProgressBus(redis)
            cleanup.append(redis.aclose)
        yield
        for fn in cleanup:
            await fn()

    app = FastAPI(title="CorpSEC API", version="0.1.0", lifespan=lifespan)
    app.state.sessions = sessions
    app.state.queue = queue
    app.state.progress = progress
    checks = load_checks()

    async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
        async with request.app.state.sessions() as session:
            yield session

    def get_queue(request: Request) -> ScanQueue:
        q: ScanQueue = request.app.state.queue
        return q

    SessionDep = Annotated[AsyncSession, Depends(get_session)]
    QueueDep = Annotated[ScanQueue, Depends(get_queue)]

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return problem(exc.status_code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return problem(422, "The request is not valid.", detail=str(exc.errors()))

    @app.exception_handler(InvalidTargetError)
    async def invalid_target(request: Request, exc: InvalidTargetError) -> JSONResponse:
        return problem(422, str(exc))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/scans", status_code=202)
    async def create_scan(
        body: ScanCreate, request: Request, session: SessionDep, queue: QueueDep
    ) -> ScanCreated:
        target = normalize_target(body.target)
        client_ip = request.client.host if request.client else None
        scan = Scan(
            id=new_id("scn"),
            target=body.target.strip(),
            host=target.host,
            registrable_domain=target.registrable_domain,
            status=ScanStatus.QUEUED,
            requested_by_ip=client_ip,
        )
        session.add(scan)
        session.add(AuditLog(actor_ip=client_ip, action="scan.create", target=target.host))
        await session.commit()
        await queue.enqueue_scan(scan.id)
        return ScanCreated(id=scan.id, status=scan.status)

    @app.get("/v1/scans/{scan_id}")
    async def get_scan(scan_id: str, session: SessionDep, lang: str = "en") -> ScanOut:
        # TODO(M5): redact evidence for anonymous / unverified viewers (spec §10.2).
        if not load_templates(lang):
            raise StarletteHTTPException(422, "That language isn't available yet.")
        scan = await session.scalar(
            select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings))
        )
        if scan is None:
            raise StarletteHTTPException(404, "We couldn't find that scan.")
        return ScanOut(
            id=scan.id,
            target=scan.target,
            host=scan.host,
            status=scan.status,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            score=scan.score,
            grade=scan.grade,
            grade_caps=scan.grade_caps or [],
            stage_grades={
                k: StageGradeOut.model_validate(v) for k, v in (scan.stage_grades or {}).items()
            },
            fix_first=scan.fix_first or [],
            error=scan.error,
            check_runs=scan.check_runs or [],
            findings=[
                FindingOut(
                    id=f.id,
                    check_id=f.check_id,
                    check_version=f.check_version,
                    host=f.host,
                    dedupe_key=f.dedupe_key,
                    severity=f.severity,
                    confidence=f.confidence,
                    status=f.status,
                    evidence=f.evidence.model_dump(mode="json"),
                    context=f.context,
                    references=f.references,
                    first_seen=f.first_seen,
                    fixed_at=f.fixed_at,
                    dismissed_reason=f.dismissed_reason,
                    explanation=explanation,
                )
                for f, explanation in explained_findings(scan, scan.findings, lang)
            ],
        )

    @app.get("/v1/scans/{scan_id}/events")
    async def scan_events(scan_id: str, request: Request, session: SessionDep) -> StreamingResponse:
        """Server-Sent Events: ``progress`` events while running, then one ``done``."""
        if await session.get(Scan, scan_id) is None:
            raise StarletteHTTPException(404, "We couldn't find that scan.")
        await session.close()
        bus: ProgressBus = request.app.state.progress
        sessions: async_sessionmaker[AsyncSession] = request.app.state.sessions

        async def status() -> str | None:
            async with sessions() as s:
                scan = await s.get(Scan, scan_id)
                return scan.status if scan else None

        async def stream() -> AsyncIterator[str]:
            # Subscribe before reading the status so a "done" can't slip in between.
            async with bus.subscribe(scan_id) as events:
                if await status() in FINISHED:
                    yield sse({"type": "done"})
                    return
                if snap := await bus.snapshot(scan_id):
                    yield sse(snap)
                inbox: asyncio.Queue[Event] = asyncio.Queue()

                async def pump() -> None:
                    async for ev in events:
                        await inbox.put(ev)

                pump_task = asyncio.create_task(pump())
                try:
                    while True:
                        try:
                            ev = await asyncio.wait_for(inbox.get(), HEARTBEAT_SECONDS)
                        except TimeoutError:
                            if await request.is_disconnected():
                                return
                            if await status() in FINISHED:  # missed "done" (worker restart)
                                yield sse({"type": "done"})
                                return
                            yield ": keep-alive\n\n"
                            continue
                        yield sse(ev)
                        if ev.get("type") == "done":
                            return
                finally:
                    pump_task.cancel()

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            # no-transform: proxies (Next.js rewrites, nginx, CDNs) must not gzip the stream,
            # or the browser only sees events once the scan has finished.
            headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
        )

    async def finding_or_404(session: AsyncSession, finding_id: str) -> FindingRow:
        row = await session.get(FindingRow, finding_id)
        if row is None:
            raise StarletteHTTPException(404, "We couldn't find that problem.")
        return row

    @app.post("/v1/findings/{finding_id}/recheck")
    async def recheck(
        finding_id: str, request: Request, session: SessionDep, queue: QueueDep
    ) -> RecheckOut:
        row = await finding_or_404(session, finding_id)
        client_ip = request.client.host if request.client else None
        session.add(AuditLog(actor_ip=client_ip, action="finding.recheck", target=row.id))
        await session.commit()
        try:
            result = await queue.recheck(finding_id)
        except TimeoutError as exc:
            raise StarletteHTTPException(504, "Checking took too long. Please try again.") from exc
        if result is None:
            raise StarletteHTTPException(409, "This is already being checked. Please wait.")
        return RecheckOut.model_validate(result)

    @app.post("/v1/findings/{finding_id}/dismiss")
    async def dismiss(
        finding_id: str, body: DismissIn, request: Request, session: SessionDep
    ) -> RecheckOut:
        row = await finding_or_404(session, finding_id)
        if row.severity == Severity.CRITICAL and body.reason != "false_positive":
            # spec §7.6: serious problems can only be dismissed as false alarms
            raise StarletteHTTPException(
                422, "Serious problems can only be hidden if they are a false alarm."
            )
        row.status = FindingStatus.DISMISSED
        row.dismissed_reason = body.reason
        client_ip = request.client.host if request.client else None
        session.add(
            AuditLog(actor_ip=client_ip, action=f"finding.dismiss.{body.reason}", target=row.id)
        )
        scan = await session.get(Scan, row.scan_id)
        assert scan is not None
        await session.flush()
        await regrade(session, scan, checks)
        await session.commit()
        return RecheckOut(result="still_present", grade=scan.grade, score=scan.score)

    @app.post("/v1/findings/{finding_id}/restore")
    async def restore(finding_id: str, request: Request, session: SessionDep) -> RecheckOut:
        row = await finding_or_404(session, finding_id)
        if row.status == FindingStatus.DISMISSED:
            row.status = FindingStatus.OPEN
            row.dismissed_reason = None
            client_ip = request.client.host if request.client else None
            session.add(AuditLog(actor_ip=client_ip, action="finding.restore", target=row.id))
        scan = await session.get(Scan, row.scan_id)
        assert scan is not None
        await session.flush()
        await regrade(session, scan, checks)
        await session.commit()
        return RecheckOut(result="still_present", grade=scan.grade, score=scan.score)

    return app


app = create_app()
