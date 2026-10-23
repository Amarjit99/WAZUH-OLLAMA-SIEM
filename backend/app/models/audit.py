"""SQLAlchemy 2.0 ORM model for audit events and tamper-evident hash chaining.

Conforms strictly to specs/PHASE_7_DATABASE_SCHEMA.md.
"""

from datetime import datetime, timezone
import uuid
from typing import Optional

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    """Generate a UUID4 hex string."""
    return str(uuid.uuid4())


class AuditEvent(Base):
    """Authoritative audit log table tracking persistence and administrative operations."""

    __tablename__ = "audit_events"

    audit_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    actor_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    resource_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    resource_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    outcome: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    request_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    client_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
    )
    metadata_json: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    previous_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    event_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    __table_args__ = (
        Index("idx_audit_timestamp", timestamp.desc()),
        Index("idx_audit_action", "action"),
        Index("idx_audit_resource", "resource_type", "resource_id"),
        Index("idx_audit_event_hash", "event_hash"),
    )
