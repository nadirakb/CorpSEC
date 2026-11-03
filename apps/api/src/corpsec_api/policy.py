"""Who may scan what (spec §10.3): opt-outs and sensitive domains."""

from __future__ import annotations

import hashlib
import hmac

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from corpsec_api.db import OptOut
from corpsec_scanner.target import ScanTarget

OPTOUT_PREFIX = "corpsec-optout="
# Public suffixes containing one of these labels belong to governments / armed forces
# (gov, gov.uk, gov.az, mil, ...). Only verified owners may scan them.
SENSITIVE_LABELS = frozenset({"gov", "mil"})


class ScanRefusedError(Exception):
    """A user-facing reason why CorpSEC won't scan this target."""


def is_sensitive(target: ScanTarget) -> bool:
    suffix = target.registrable_domain.split(".", 1)[1] if "." in target.registrable_domain else ""
    return any(label in SENSITIVE_LABELS for label in suffix.split("."))


def optout_token(domain: str, secret: str) -> str:
    """Deterministic per domain, so nothing needs storing until the owner proves control."""
    digest = hmac.new(secret.encode(), domain.lower().encode(), hashlib.sha256).hexdigest()
    return digest[:32]


async def is_opted_out(session: AsyncSession, domain: str) -> bool:
    return await session.scalar(select(OptOut).where(OptOut.domain == domain.lower())) is not None


async def check_target(session: AsyncSession, target: ScanTarget, *, verified_owner: bool) -> None:
    if await is_opted_out(session, target.registrable_domain):
        raise ScanRefusedError("The owner of this domain asked us not to check it.")
    if is_sensitive(target) and not verified_owner:
        raise ScanRefusedError(
            "Government and military sites can only be checked by their verified owners."
        )
