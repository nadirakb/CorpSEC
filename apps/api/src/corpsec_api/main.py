"""CorpSEC HTTP API (spec §13). Run: ``uvicorn corpsec_api.main:app``.

No ``from __future__ import annotations`` here: FastAPI must resolve the dependency
aliases defined inside ``create_app`` at runtime.
"""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api.db import AuditLog, Scan, make_engine
from corpsec_api.queue import ArqScanQueue, ScanQueue
from corpsec_api.reporting import explained_findings
from corpsec_api.settings import get_settings
from corpsec_checks.explain import Explanation, load_templates
from corpsec_scanner import InvalidTargetError, ScanStatus, normalize_target
from corpsec_scanner.models import new_id


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
            cleanup.append(redis.aclose)
        yield
        for fn in cleanup:
            await fn()

    app = FastAPI(title="CorpSEC API", version="0.1.0", lifespan=lifespan)
    app.state.sessions = sessions
    app.state.queue = queue

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
                    explanation=explanation,
                )
                for f, explanation in explained_findings(scan, scan.findings, lang)
            ],
        )

    return app


app = create_app()
