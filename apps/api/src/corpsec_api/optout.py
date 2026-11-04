"""Opt-out for site owners who don't want CorpSEC to check their domain (spec §10.3).

The owner proves control with a DNS TXT record; no account is needed. The token is an HMAC
of the domain, so nothing is stored until the proof succeeds.

No ``from __future__ import annotations``: FastAPI resolves annotations at runtime.
"""

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api import events
from corpsec_api.db import AuditLog, OptOut
from corpsec_api.deps import SessionDep, client_ip
from corpsec_api.policy import OPTOUT_PREFIX, is_opted_out, optout_token
from corpsec_api.settings import Settings
from corpsec_scanner.dns import DnsClient, DnsError
from corpsec_scanner.models import utcnow
from corpsec_scanner.target import normalize_target

router = APIRouter(prefix="/v1/optout", tags=["opt-out"])


class OptOutIn(BaseModel):
    domain: str = Field(max_length=2048)


class OptOutInfo(BaseModel):
    domain: str
    txt_name: str
    txt_value: str
    opted_out: bool


def _domain(raw: str) -> str:
    return normalize_target(raw).registrable_domain


@router.get("/{domain}")
async def optout_instructions(domain: str, request: Request, session: SessionDep) -> OptOutInfo:
    settings: Settings = request.app.state.settings
    d = _domain(domain)
    return OptOutInfo(
        domain=d,
        txt_name=d,
        txt_value=f"{OPTOUT_PREFIX}{optout_token(d, settings.secret_key)}",
        opted_out=await is_opted_out(session, d),
    )


@router.post("")
async def confirm_optout(body: OptOutIn, request: Request, session: SessionDep) -> OptOutInfo:
    settings: Settings = request.app.state.settings
    d = _domain(body.domain)
    expected = f"{OPTOUT_PREFIX}{optout_token(d, settings.secret_key)}"
    dns: DnsClient = getattr(request.app.state, "dns", None) or DnsClient()
    try:
        records = await dns.resolve(d, "TXT")
    except DnsError as exc:
        raise StarletteHTTPException(
            503, "We couldn't look up the domain. Try again soon."
        ) from exc
    if expected not in (r.strip() for r in records):
        raise StarletteHTTPException(
            422, "We couldn't find the TXT record yet. DNS changes can take up to an hour."
        )
    if not await is_opted_out(session, d):
        session.add(OptOut(domain=d, verified_at=utcnow()))
        session.add(AuditLog(actor_ip=client_ip(request), action="optout", target=d))
        events.record(session, events.OPTOUT_ADDED)
        await session.commit()
    return OptOutInfo(domain=d, txt_name=d, txt_value=expected, opted_out=True)
