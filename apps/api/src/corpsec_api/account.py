"""Account self-service (spec §15): export everything we hold about you, delete it all,
and the weekly digest preference.

No ``from __future__ import annotations``: FastAPI resolves annotations at runtime.
"""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import delete, select
from starlette.exceptions import HTTPException as StarletteHTTPException

from corpsec_api.auth import MeOut
from corpsec_api.db import (
    Alert,
    AuditLog,
    FindingRow,
    LoginToken,
    Scan,
    ShareLink,
    Site,
    User,
    UserIdentity,
)
from corpsec_api.deps import SESSION_COOKIE, CurrentUser, SessionDep, client_ip
from corpsec_scanner.models import utcnow

router = APIRouter(prefix="/v1/me", tags=["account"])


class AccountPatch(BaseModel):
    weekly_digest: bool | None = None


class DeleteIn(BaseModel):
    confirm_email: str
    """The account's email, typed again: deleting can't be undone."""


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


@router.patch("")
async def update_account(body: AccountPatch, user: CurrentUser, session: SessionDep) -> MeOut:
    db_user = await session.get(User, user.id)
    assert db_user is not None
    if body.weekly_digest is not None:
        db_user.weekly_digest = body.weekly_digest
    await session.commit()
    return MeOut(id=db_user.id, email=db_user.email, weekly_digest=db_user.weekly_digest)


@router.get("/export")
async def export_account(user: CurrentUser, session: SessionDep) -> JSONResponse:
    """Everything stored about the signed-in person, as one JSON download (GDPR art. 15/20)."""
    sites = (await session.scalars(select(Site).where(Site.owner_id == user.id))).all()
    site_ids = [s.id for s in sites]
    scans = (
        (await session.scalars(select(Scan).where(Scan.site_id.in_(site_ids)))).all()
        if site_ids
        else []
    )
    scan_ids = [s.id for s in scans]
    findings = (
        (await session.scalars(select(FindingRow).where(FindingRow.scan_id.in_(scan_ids)))).all()
        if scan_ids
        else []
    )
    alerts = (
        (await session.scalars(select(Alert).where(Alert.site_id.in_(site_ids)))).all()
        if site_ids
        else []
    )
    identities = (
        await session.scalars(select(UserIdentity).where(UserIdentity.user_id == user.id))
    ).all()
    shares = (await session.scalars(select(ShareLink).where(ShareLink.created_by == user.id))).all()
    audit = (
        await session.scalars(
            select(AuditLog).where(AuditLog.actor_user_id == user.id).order_by(AuditLog.at)
        )
    ).all()

    data: dict[str, Any] = {
        "exported_at": utcnow().isoformat(),
        "account": {
            "id": user.id,
            "email": user.email,
            "created_at": _iso(user.created_at),
            "last_login_at": _iso(user.last_login_at),
            "weekly_digest": user.weekly_digest,
            "sign_in_providers": [{"provider": i.provider, "email": i.email} for i in identities],
        },
        "sites": [
            {
                "domain": s.domain,
                "platform": s.platform,
                "verified_at": _iso(s.verified_at),
                "verification_method": s.verification_method,
                "monitoring_enabled": s.monitoring_enabled,
                "created_at": _iso(s.created_at),
                "scans": [
                    {
                        "id": sc.id,
                        "status": sc.status,
                        "grade": sc.grade,
                        "score": sc.score,
                        "finished_at": _iso(sc.finished_at),
                        "findings": [
                            {
                                "check_id": f.check_id,
                                "host": f.host,
                                "item": f.dedupe_key,
                                "severity": f.severity,
                                "status": f.status,
                                "first_seen": _iso(f.first_seen),
                                "evidence": f.evidence,
                            }
                            for f in findings
                            if f.scan_id == sc.id
                        ],
                    }
                    for sc in scans
                    if sc.site_id == s.id
                ],
                "alerts": [
                    {"kind": a.kind, "sent_at": _iso(a.sent_at), "details": a.payload}
                    for a in alerts
                    if a.site_id == s.id
                ],
            }
            for s in sites
        ],
        "shared_reports": [
            {"scan_id": sh.scan_id, "recipient": sh.recipient, "expires_at": _iso(sh.expires_at)}
            for sh in shares
        ],
        "activity_log": [
            {"action": a.action, "target": a.target, "ip": a.actor_ip, "at": _iso(a.at)}
            for a in audit
        ],
    }
    return JSONResponse(
        data,
        headers={"Content-Disposition": 'attachment; filename="corpsec-account.json"'},
    )


@router.delete("", status_code=204)
async def delete_account(
    body: DeleteIn, request: Request, response: Response, user: CurrentUser, session: SessionDep
) -> Response:
    if body.confirm_email.strip().lower() != user.email.lower():
        raise StarletteHTTPException(422, "Type your email address exactly to confirm.")
    site_ids = select(Site.id).where(Site.owner_id == user.id)
    # Scans of the user's sites go too: with their site gone they would otherwise become
    # public, link-shared reports. Sites, sessions, sign-in links via OAuth, share links and
    # identities cascade from the user row.
    await session.execute(delete(Scan).where(Scan.site_id.in_(site_ids)))
    await session.execute(delete(LoginToken).where(LoginToken.email == user.email))
    # The abuse log keeps the action for its normal retention (1 year), without the email.
    session.add(
        AuditLog(
            actor_user_id=user.id,
            actor_ip=client_ip(request),
            action="account.delete",
            target=user.id,
        )
    )
    db_user = await session.get(User, user.id)
    await session.delete(db_user)
    await session.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.status_code = 204
    return response
