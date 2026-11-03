"""Request dependencies: database session, queue, mailer, settings and the signed-in user.

No ``from __future__ import annotations``: FastAPI resolves these annotations at runtime.
"""

import hashlib
import ipaddress
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api.db import User, UserSession
from corpsec_api.mailer import Mailer
from corpsec_api.oidc import OidcClient
from corpsec_api.queue import ScanQueue
from corpsec_api.settings import Settings
from corpsec_scanner.models import utcnow

SESSION_COOKIE = "corpsec_session"


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.sessions() as session:
        yield session


def get_queue(request: Request) -> ScanQueue:
    q: ScanQueue = request.app.state.queue
    return q


def get_mailer(request: Request) -> Mailer:
    m: Mailer = request.app.state.mailer
    return m


def get_oidc(request: Request) -> OidcClient:
    c: OidcClient = request.app.state.oidc
    return c


def get_app_settings(request: Request) -> Settings:
    s: Settings = request.app.state.settings
    return s


SessionDep = Annotated[AsyncSession, Depends(get_db)]
QueueDep = Annotated[ScanQueue, Depends(get_queue)]
MailerDep = Annotated[Mailer, Depends(get_mailer)]
SettingsDep = Annotated[Settings, Depends(get_app_settings)]
OidcDep = Annotated[OidcClient, Depends(get_oidc)]


async def optional_user(request: Request, session: SessionDep) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    row = await session.scalar(
        select(UserSession).where(UserSession.token_hash == token_hash(token))
    )
    now = utcnow()
    if row is None or row.expires_at <= now:
        return None
    user = await session.get(User, row.user_id)
    if user is None or user.deleted_at is not None:
        return None
    if row.last_seen_at is None or now - row.last_seen_at > timedelta(minutes=5):
        row.last_seen_at = now
        await session.commit()
    return user


async def current_user(user: Annotated[User | None, Depends(optional_user)]) -> User:
    if user is None:
        raise StarletteHTTPException(401, "Please sign in to continue.")
    return user


OptionalUser = Annotated[User | None, Depends(optional_user)]
CurrentUser = Annotated[User, Depends(current_user)]


def client_ip(request: Request) -> str | None:
    """The visitor's address. X-Forwarded-For is only believed when the request comes from
    a configured proxy, and only its last entry (the one that proxy added or overwrote)."""
    peer = request.client.host if request.client else None
    settings: Settings = request.app.state.settings
    if peer is None or not _is_trusted(peer, settings.trusted_proxies):
        return peer
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return peer
    candidate = forwarded.split(",")[-1].strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return peer
    return candidate


def _is_trusted(address: str, networks: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(n, strict=False) for n in networks)
