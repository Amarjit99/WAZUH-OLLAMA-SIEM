"""SQLAlchemy 2.0 ORM model for Case Management.

Conforms strictly to specs/PRD.md (FR-030) and specs/API_CONTRACT.md.
"""

from datetime import datetime, timezone
import uuid
from typing import Optional

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


def generate_case_id() -> str:
    """Generate a stable case identifier."""
    return f"case-{uuid.uuid4().hex[:12]}"


class Case(Base):
    """Authoritative case management entity linking alerts, investigations, and analyst notes."""

    __tablename__ = "cases"

    case_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_case_id,
    )
    title: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="open",  # "open", "in_progress", "closed"
    )
    priority: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="medium",  # "low", "medium", "high", "critical"
    )
    assignee: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    alert_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    investigation_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("investigations.investigation_id", ondelete="SET NULL"),
        nullable=True,
    )
    analyst_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationship to parent investigation if linked
    investigation = relationship(
        "Investigation",
        foreign_keys=[investigation_id],
        lazy="selectin",
    )

    __table_args__ = (
        Index("idx_cases_status", "status"),
        Index("idx_cases_priority", "priority"),
        Index("idx_cases_created_at", created_at.desc()),
        Index("idx_cases_alert_id", "alert_id"),
        Index("idx_cases_investigation_id", "investigation_id"),
        Index("idx_cases_assignee", "assignee"),
    )
