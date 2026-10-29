"""SQLAlchemy models for the MVP data model (spec §12)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONB, list[Any]: JSONB}  # noqa: RUF012


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    locale: Mapped[str] = mapped_column(String(16), default="en")
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Site(TimestampMixin, Base):
    __tablename__ = "sites"
    __table_args__ = (UniqueConstraint("owner_id", "domain"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    domain: Mapped[str] = mapped_column(String(253))
    platform: Mapped[str | None] = mapped_column(String(40))
    email_provider: Mapped[str | None] = mapped_column(String(40))
    verification_method: Mapped[str | None] = mapped_column(String(16))
    verification_token: Mapped[str | None] = mapped_column(String(64))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=False)


class Scan(TimestampMixin, Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_site_created", "site_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    site_id: Mapped[str | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    target: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(String(253))
    registrable_domain: Mapped[str] = mapped_column(String(253), index=True)
    status: Mapped[str] = mapped_column(String(16))
    catalog_version: Mapped[str | None] = mapped_column(String(32))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    score: Mapped[int | None] = mapped_column(Integer)
    grade: Mapped[str | None] = mapped_column(String(2))
    stage_grades: Mapped[dict[str, Any] | None] = mapped_column()
    grade_caps: Mapped[list[Any] | None] = mapped_column()
    fix_first: Mapped[list[Any] | None] = mapped_column()
    """Finding ids to fix first (max 3), from the grader."""
    grade_model_version: Mapped[str | None] = mapped_column(String(16))
    check_runs: Mapped[list[Any] | None] = mapped_column()
    error: Mapped[str | None] = mapped_column(Text)
    requested_by_ip: Mapped[str | None] = mapped_column(String(45))

    findings: Mapped[list[FindingRow]] = relationship(
        back_populates="scan", order_by="FindingRow.created_at", lazy="raise"
    )


class FindingRow(TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_dedupe", "site_id", "check_id", "host", "dedupe_key"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    site_id: Mapped[str | None] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    check_id: Mapped[str] = mapped_column(String(16))
    check_version: Mapped[str] = mapped_column(String(16))
    host: Mapped[str] = mapped_column(String(253))
    dedupe_key: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    evidence: Mapped[dict[str, Any]] = mapped_column()
    context: Mapped[dict[str, Any]] = mapped_column(default=dict)
    references: Mapped[list[Any]] = mapped_column(default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dismissed_reason: Mapped[str | None] = mapped_column(String(32))

    scan: Mapped[Scan] = relationship(back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(40))
    actor_ip: Mapped[str | None] = mapped_column(String(45))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)
