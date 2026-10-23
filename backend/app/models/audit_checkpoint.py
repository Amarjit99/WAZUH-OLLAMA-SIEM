"""SQLAlchemy 2.0 ORM model for audit checkpoints.

Conforms strictly to specs/PHASE_7_5_CHECKPOINT_PROTOCOL.md and approved ADR-013.
"""

from datetime import datetime, timezone
import uuid
from typing import Optional

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    """Generate a UUID4 hex string."""
    return str(uuid.uuid4())


class AuditCheckpoint(Base):
    """Authoritative checkpoint record anchoring retained audit suffix and offline archives."""

    __tablename__ = "audit_checkpoints"

    checkpoint_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )
    schema_version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="v1",
    )
    checkpoint_sequence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        unique=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    interval_start_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    interval_end_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    first_included_audit_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
    )
    last_included_audit_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
    )
    last_included_event_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    event_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    pruned_events_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    previous_checkpoint_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
    )
    previous_checkpoint_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    checkpoint_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    signature_algorithm: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="NONE",
    )
    signature_value: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    signing_key_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    archive_file_path: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    archive_sha256: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="ACTIVE",
    )

    __table_args__ = (
        Index("idx_checkpoints_seq", "checkpoint_sequence"),
        Index("idx_checkpoints_hash", "checkpoint_digest"),
        Index("idx_checkpoints_last_event", "last_included_event_hash"),
    )
